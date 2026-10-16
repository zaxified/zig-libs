// SPDX-License-Identifier: MIT
//! Brotli encoder (RFC 7932): LZ77 backward references + a per-meta-block
//! Huffman (prefix) code for literals, insert-and-copy commands and distances,
//! with a **store-mode fallback** that bounds the worst case.
//!
//! ## What it emits
//!
//! One meta-block per `CompressOptions.block_size` (default 1 MiB) of input.
//! Each block is tried as a compressed meta-block first (`NBLTYPES = 1` for
//! all three categories, `NPOSTFIX = NDIRECT = 0`) and is kept only if it came
//! out **strictly smaller** than storing those bytes verbatim; otherwise the
//! block is rolled back out of the bit writer and re-emitted as an
//! uncompressed meta-block. The fallback is therefore a real, exercised path,
//! not an accident — see the `fallback` tests.
//!
//! Inside a compressed block (2026-09-30):
//!
//! - **Matches are chosen by the bits they save** (`Matcher.gain`), not by
//!   length: the literals covered, priced at the block's order-0 entropy,
//!   minus the distance's cost. Up to 65 535 bytes long; the search depth is
//!   the effort (`Effort`: 32 / 256 candidates of a bucketed hash), one lazy
//!   step. At `.q6`/`.q9` the last two distances are tried first (a
//!   copy at one of them needs no distance bits, from 3 bytes on).
//! - **`.q4` is its own algorithm** (`FastMatcher`, `buildCommandsFast`):
//!   4 slots of a 6-byte hash and the last distance, a lazy step only below
//!   32 bytes, sparse inserts inside long copies, growing steps through long
//!   literal runs. Sizes about google/brotli quality 4 (2026-10-14).
//! - **Distance short codes and implicit distances**: the encoder mirrors the
//!   decoder's ring of the last four distances (`DistRing`) and names a
//!   distance by its short code (0..15, no extra bits) when it can; a copy at
//!   the last distance whose lengths fit uses an implicit-distance command
//!   and no distance symbol at all.
//! - **Literal context modelling** (not at `.q4`): per-context histograms
//!   for the UTF8 and LSB6 modes, clustered greedily by estimated bits into
//!   at most 16 codes, the cheaper mode kept — and then checked on real bits
//!   against a single literal code, keeping the shorter block.
//! - **Distance contexts** (2026-10-15): the four distance contexts (copy
//!   length 2, 3, 4, 5+) share one to four codes, the cheapest partition.
//! - **`.q11`** (2026-10-15): a shortest-path parse priced from the block's
//!   own statistics (`buildCommandsOptimal`) and static-dictionary words
//!   with their transforms (`DictSearch`); three parses, the shortest as
//!   written kept.
//! - **Static-dictionary words at `.q9`** (2026-10-15, R15): where the hash
//!   finds no copy, the word google/brotli's qualities 5–9 would try
//!   (`Matcher.findWord`, `dictionary_hash.zig`), whole or with its end cut.
//!
//! ## What it deliberately does not do
//!
//! - No `NPOSTFIX`/`NDIRECT` below `.q11`, no OMIT_FIRST dictionary
//!   transforms, no dictionary words at `.q6` (5–10 % of its time for
//!   0.25–0.7 % of size on text, 2026-10-15).
//!
//! The result (2026-10-16): `alice29.txt` 52 275 bytes at `.q6` (google/brotli
//! q6: 51 967), 50 994 at `.q9` (q9: 51 054), 46 378 at `.q11` (q11: 46 487);
//! never worse than store mode by more than the two-bit final-meta-block
//! marker.
//!
//! ## How the bit-level format is anchored
//!
//! `decoder.zig` is the specification this file writes against — every field
//! order and every bit order below mirrors the corresponding read in
//! `decodeCompressedMetablock` / `readComplexHuffman` / `runCommands`. Because
//! a writer and a reader can share a misreading of RFC 7932 and still round
//! trip perfectly, correctness is anchored *outside* this repository: see
//! `tools/interop.zig`, which pushes this encoder's output through the
//! reference implementation (google/brotli via Python `brotli`), and
//! `interop_replay_test.zig`, which holds the reference's verdict on every
//! stream it accepted without needing that implementation present.

const std = @import("std");
const huffman = @import("huffman.zig");
const tables = @import("tables.zig");
const dictionary = @import("dictionary.zig");
const transforms = @import("transforms.zig");
const block_split = @import("block_split.zig");
const greedy_split = @import("greedy_split.zig");
const dictionary_hash = @import("dictionary_hash.zig");
const PreparedDictionary = @import("prepared_dictionary.zig").PreparedDictionary;
const BrotliError = @import("errors.zig").BrotliError;

// ---------------------------------------------------------------------------
// Tunables.

/// Maximum bytes per uncompressed meta-block (MLEN is a 24-bit field + 1).
const max_store_block = 1 << 24;
/// Bytes of input per compressed meta-block. Bigger amortises the ~100-300
/// byte prefix-code header better; smaller adapts to changing statistics.
pub const compressed_block_size = 1 << 20;

const min_match = 4;
/// Shortest copy taken at a distance the decoder's ring already holds: it
/// costs no distance bits, so a few covered literals pay for it. Two bytes
/// at the last distance are an implicit-distance command — google q5/q11
/// leave thousands of them on fonts (2026-10-15); the greedy matcher takes
/// two at the last two, three at the others — google q5–q9's rule
/// (`FindLongestMatch`: `len == 2 && i < 2`). With `.q6`'s sparse search
/// a 64 KiB font got 1 331 copies with it, 315 without (google q6: 1 298),
/// and 1.6 % smaller; text ±0.1 % (2026-10-16).
const min_ring_match = 2;
/// Longest match searched for. Long runs (a file of zeros) are where a short
/// cap hurt most: 512 left `zeros` at 651 bytes, 65 535 at 26 (the reference's
/// q11: 14). Copy lengths themselves reach far higher (RFC 7932 copy code 23).
const max_match = 65535;

/// Errors that make the encoder give up on *compressing* a block. They never
/// escape `compress`: the block is stored verbatim instead.
/// `NotSmaller`: the block would not come out shorter than stored
/// (`writeFragmentBlock` knows before it writes the commands).
const GiveUp = error{ EncoderInvariant, NotSmaller } || BrotliError;

// ---------------------------------------------------------------------------
// Bit writer (LSB-first, matching `BitReader`).

const BitWriter = struct {
    buf: std.ArrayListUnmanaged(u8) = .empty,
    acc: u64 = 0,
    cnt: u6 = 0,
    gpa: std.mem.Allocator,
    /// `buf` is the caller's (`compressInto`): never grown or freed. Running
    /// out of it is `error.OutOfMemory` with `overflowed` set: mid-block,
    /// `Core.compressBlock` decides the block in a scratch writer instead;
    /// anywhere else the output does not fit.
    fixed: bool = false,
    overflowed: bool = false,

    /// Room for `n` more bytes.
    inline fn room(self: *BitWriter, n: usize) std.mem.Allocator.Error!void {
        if (self.buf.capacity - self.buf.items.len >= n) return;
        if (self.fixed) {
            self.overflowed = true;
            return error.OutOfMemory;
        }
        try self.buf.ensureUnusedCapacity(self.gpa, n);
    }

    /// Up to 32 bits. The accumulator holds up to 31 pending bits between
    /// calls and goes out four bytes at a time (a byte per `append` was most
    /// of `writeCompressedBlock`'s time, bench 2026-10-11).
    inline fn writeBits(self: *BitWriter, val: u32, n: u6) std.mem.Allocator.Error!void {
        const m: u64 = (@as(u64, 1) << n) - 1;
        self.acc |= (@as(u64, val) & m) << self.cnt;
        self.cnt += n;
        if (self.cnt >= 32) {
            try self.room(4);
            self.buf.appendSliceAssumeCapacity(&std.mem.toBytes(std.mem.nativeToLittle(u32, @truncate(self.acc))));
            self.acc >>= 32;
            self.cnt -= 32;
        }
    }

    /// Write out every pending bit, the last byte zero-padded.
    fn alignToByte(self: *BitWriter) std.mem.Allocator.Error!void {
        while (self.cnt >= 8) {
            try self.room(1);
            self.buf.appendAssumeCapacity(@truncate(self.acc));
            self.acc >>= 8;
            self.cnt -= 8;
        }
        if (self.cnt != 0) {
            try self.room(1);
            self.buf.appendAssumeCapacity(@truncate(self.acc & 0xff));
            self.acc = 0;
            self.cnt = 0;
        }
    }

    /// Precondition: byte aligned (`alignToByte`).
    fn writeBytes(self: *BitWriter, bytes: []const u8) std.mem.Allocator.Error!void {
        try self.room(bytes.len);
        self.buf.appendSliceAssumeCapacity(bytes);
    }

    /// A writer that continues from `m` of another (same pending bits), for
    /// writing an alternative into a scratch buffer.
    fn resumeAt(self: *BitWriter, m: Mark) void {
        self.buf.clearRetainingCapacity();
        self.acc = m.acc;
        self.cnt = m.cnt;
    }

    /// Replace everything written since `m` with what `alt` (resumed at the
    /// same `m`) holds.
    fn takeFrom(self: *BitWriter, m: Mark, alt: *const BitWriter) std.mem.Allocator.Error!void {
        self.rollback(m);
        try self.room(alt.buf.items.len);
        self.buf.appendSliceAssumeCapacity(alt.buf.items);
        self.acc = alt.acc;
        self.cnt = alt.cnt;
    }

    /// Absolute bit position, used to price a block against its alternative.
    fn bitPos(self: *const BitWriter) usize {
        return self.buf.items.len * 8 + self.cnt;
    }

    const Mark = struct { len: usize, acc: u64, cnt: u6 };

    fn mark(self: *const BitWriter) Mark {
        return .{ .len = self.buf.items.len, .acc = self.acc, .cnt = self.cnt };
    }

    /// Undo everything written since `m`. Capacity is retained, so a rolled
    /// back block costs no allocation churn.
    fn rollback(self: *BitWriter, m: Mark) void {
        self.buf.shrinkRetainingCapacity(m.len);
        self.acc = m.acc;
        self.cnt = m.cnt;
    }
};

// ---------------------------------------------------------------------------
// The fixed prefix code for code-length symbols (RFC 7932 3.5), inverted.
//
// `readComplexHuffman` peeks 4 bits and looks the value up in
// `code_length_prefix_{length,value}`. Writing is the inverse map, derived from
// those same tables at comptime so it can never drift from what the decoder
// reads: for each 4-bit pattern whose *high* bits above its code length are
// zero, the low `length` bits ARE the code for `value`.

const ClPrefix = struct { bits: u4, len: u3 };

const cl_prefix: [6]ClPrefix = blk: {
    var out: [6]ClPrefix = .{ClPrefix{ .bits = 0, .len = 0 }} ** 6;
    var found = [_]bool{false} ** 6;
    for (tables.code_length_prefix_length, tables.code_length_prefix_value, 0..) |len, val, b4| {
        if (b4 >> @as(u3, @intCast(len)) != 0) continue; // a longer alias of the same code
        if (found[val]) @compileError("code-length prefix code is ambiguous");
        found[val] = true;
        out[val] = .{ .bits = @intCast(b4), .len = @intCast(len) };
    }
    for (found) |f| if (!f) @compileError("code-length prefix code is incomplete");
    break :blk out;
};

// ---------------------------------------------------------------------------
// Distance codes for NPOSTFIX = 0, NDIRECT = 0 — the mirror image of
// `Decoder.calculateDistanceLut` for that (only) configuration.

const dist_alphabet_size = tables.distanceAlphabetSize(0, 0, tables.max_distance_bits);
/// A large-window stream's valid distance codes (`tables.distanceLimit`):
/// up to 0x7FFFFFFC, past any window this encoder makes (2^30).
const dist_alphabet_large = tables.distanceLimit(0, 0);
/// The alphabet a large-window stream's distance codes are read as from: a
/// simple code's symbols are this wide.
const dist_alphabet_large_max = tables.distanceAlphabetSize(0, 0, tables.large_max_distance_bits);

const DistCode = struct { offset: u32, nbits: u5 };

const DistSym = struct { sym: u16, extra: u32, nbits: u5 };

/// NPOSTFIX and NDIRECT (RFC 7932 §4) of a meta-block.
const DistParams = struct {
    npostfix: u2 = 0,
    /// A multiple of `1 << npostfix`, below `16 << npostfix`.
    ndirect: u8 = 0,

    /// The distance alphabet of a meta-block with these parameters (not a
    /// large window).
    fn alphabet(p: DistParams) u32 {
        return tables.distanceAlphabetSize(p.npostfix, p.ndirect, tables.max_distance_bits);
    }
};

/// The largest distance alphabet a meta-block may have (NPOSTFIX 3, NDIRECT
/// 120), or a large window's.
const dist_alphabet_max = @max(dist_alphabet_large, (DistParams{ .npostfix = 3, .ndirect = 120 }).alphabet());

/// A meta-block's distance parameters and alphabet size (`n`: the
/// parameters' alphabet, or a large window's).
const DistAlphabet = struct {
    p: DistParams = .{},
    n: usize,

    fn code(a: DistAlphabet, d: u32) ?DistSym {
        return distanceCodeWith(d, a.p, a.n);
    }
};

/// `distanceCode` for any NPOSTFIX/NDIRECT (google `PrefixEncodeCopyDistance`).
fn distanceCodeWith(d: u32, p: DistParams, n: usize) ?DistSym {
    if (p.npostfix == 0 and p.ndirect == 0) return distanceCode(d, n);
    if (d == 0) return null;
    if (d <= p.ndirect) return .{ .sym = @intCast(tables.num_distance_short_codes + d - 1), .extra = 0, .nbits = 0 };
    const np: u6 = p.npostfix;
    const x: u64 = (@as(u64, 1) << (np + 2)) + d - 1 - p.ndirect;
    const bucket: u6 = @intCast(std.math.log2_int(u64, x) - 1);
    const postfix = x & ((@as(u64, 1) << np) - 1);
    const half = (x >> bucket) & 1;
    const nbits = bucket - np;
    const c: u64 = tables.num_distance_short_codes + p.ndirect + ((2 * (@as(u64, nbits) - 1) + half) << np) + postfix;
    if (c >= n) return null;
    return .{ .sym = @intCast(c), .extra = @intCast((x - ((2 + half) << bucket)) >> np), .nbits = @intCast(nbits) };
}

const dist_lut: [dist_alphabet_large]DistCode = blk: {
    var out: [dist_alphabet_large]DistCode = .{DistCode{ .offset = 0, .nbits = 0 }} ** dist_alphabet_large;
    var bits: u32 = 1;
    var half: u32 = 0;
    var i: usize = tables.num_distance_short_codes;
    while (i < dist_alphabet_large) {
        out[i] = .{ .offset = ((2 + half) << bits) - 4 + 1, .nbits = bits };
        i += 1;
        bits += half;
        half ^= 1;
    }
    break :blk out;
};

/// Smallest explicit distance code (>= 16) whose range contains `d`, or null
/// when `d` is outside the first `n` codes (`dist_alphabet_size`, or
/// `dist_alphabet_large` in a large-window stream).
/// With NPOSTFIX = NDIRECT = 0 the code follows from `d + 3`'s top bits:
/// `nbits = log2(d + 3) - 1`, the bit below the top one picks the half
/// (`dist_lut` is the same recurrence written out; the scan this replaced
/// was 5-10 % of `.q11`).
fn distanceCode(d: u32, n: usize) ?DistSym {
    if (d == 0) return null;
    const x: u64 = @as(u64, d) + 3;
    const nbits: u6 = @intCast(std.math.log2_int(u64, x) - 1);
    const half: u64 = (x >> nbits) & 1;
    const c: usize = tables.num_distance_short_codes + 2 * (@as(usize, nbits) - 1) + @as(usize, @intCast(half));
    if (c >= n) return null;
    return .{ .sym = @intCast(c), .extra = @intCast(x - ((2 + half) << nbits)), .nbits = @intCast(nbits) };
}

/// The decoder's ring of the last four distances, as RFC 7932 §4 defines it,
/// so the encoder can name a distance by a short code (0..15, no extra bits)
/// when the decoder will compute the same one. Code 0 (the last distance) and
/// the implicit-distance commands leave the ring as it is; every other code
/// pushes its distance. It persists across meta-blocks, as the decoder's does
/// — and so must be rolled back with a block that is stored instead.
const DistRing = struct {
    /// Most recent first; the RFC's initial values.
    last: [4]u32 = .{ 4, 11, 15, 16 },

    /// `packed_deltas` of the decoder: codes 4..9 are last-1, last+1, last-2,
    /// last+2, last-3, last+3; codes 10..15 the same around the second-last.
    const deltas = [6]i64{ -1, 1, -2, 2, -3, 3 };

    fn shortCode(self: *const DistRing, d: u32) ?u16 {
        for (self.last, 0..) |l, i| {
            if (l == d) return @intCast(i);
        }
        // Within 3 of the last or second-last: `d + 3 - last` is 0..6 and
        // picks the code from a nibble table (google/brotli
        // `ComputeDistanceCode`; the `deltas` loop it replaces was a tenth
        // of `.q4`'s block writer, 2026-10-16).
        const o0 = @as(u64, d) +% 3 -% self.last[0];
        if (o0 < 7) return @intCast(@as(u32, 0x9750468) >> @intCast(4 * o0) & 0xf);
        const o1 = @as(u64, d) +% 3 -% self.last[1];
        if (o1 < 7) return @intCast(@as(u32, 0xfdb1ace) >> @intCast(4 * o1) & 0xf);
        return null;
    }

    /// Account for one copy at distance `d` named by `code` (0..15, or null
    /// for an explicit code).
    fn update(self: *DistRing, d: u32, code: ?u16) void {
        if (code == 0) return;
        // Through a copy: assigned in place, the literal's first element
        // would overwrite `last[0]` before it is read for the second (the
        // ring was `{d, d, d, d}` until 2026-10-15).
        const l = self.last;
        self.last = .{ d, l[0], l[1], l[2] };
    }
};

// ---------------------------------------------------------------------------
// Insert-and-copy command tables, derived from `tables.cmd_lut` (the authority
// the decoder itself uses) rather than re-deriving the RFC's ranges by hand.

const CmdTables = struct {
    insert_off: [24]u32,
    insert_nbits: [24]u5,
    copy_off: [24]u32,
    copy_nbits: [24]u5,
    /// `sym[insert_code][copy_code]` for the explicit-distance form.
    sym: [24][24]u16,
    /// The implicit-distance form (distance = the last one, no distance
    /// symbol at all), where one exists: insert codes 0..7 with copy codes
    /// 0..15. `0xffff` elsewhere.
    implicit: [24][24]u16,
};

const cmd_tables: CmdTables = blk: {
    @setEvalBranchQuota(2_000_000);

    // The 24 distinct insert/copy length offsets, ascending. Offsets are
    // strictly increasing with the code index, so sorted-unique == code order.
    var ins: [24]u32 = .{0} ** 24;
    var cpy: [24]u32 = .{0} ** 24;
    var n_ins: usize = 0;
    var n_cpy: usize = 0;
    for (tables.cmd_lut) |e| {
        n_ins = insertSorted(&ins, n_ins, e.insert_len_offset);
        n_cpy = insertSorted(&cpy, n_cpy, e.copy_len_offset);
    }
    if (n_ins != 24 or n_cpy != 24) @compileError("cmd_lut does not have 24 insert/copy codes");

    var t: CmdTables = .{
        .insert_off = ins,
        .insert_nbits = .{0} ** 24,
        .copy_off = cpy,
        .copy_nbits = .{0} ** 24,
        .sym = .{.{0xffff} ** 24} ** 24,
        .implicit = .{.{0xffff} ** 24} ** 24,
    };
    for (tables.cmd_lut, 0..) |e, s| {
        const ic = indexOf(&ins, e.insert_len_offset);
        const cc = indexOf(&cpy, e.copy_len_offset);
        t.insert_nbits[ic] = @intCast(e.insert_len_extra_bits);
        t.copy_nbits[cc] = @intCast(e.copy_len_extra_bits);
        if (e.distance_code < 0) t.sym[ic][cc] = @intCast(s) else t.implicit[ic][cc] = @intCast(s);
    }
    for (t.sym) |row| for (row) |s| {
        if (s == 0xffff) @compileError("no explicit-distance command symbol for some (insert, copy) pair");
    };
    break :blk t;
};

fn insertSorted(arr: *[24]u32, n: usize, v: u32) usize {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (arr[i] == v) return n;
        if (arr[i] > v) break;
    }
    if (n == 24) @compileError("more than 24 distinct length offsets");
    var j: usize = n;
    while (j > i) : (j -= 1) arr[j] = arr[j - 1];
    arr[i] = v;
    return n + 1;
}

fn indexOf(arr: *const [24]u32, v: u32) usize {
    for (arr, 0..) |x, i| if (x == v) return i;
    unreachable;
}

/// Largest length code whose range contains `len`. Lengths below
/// `length_lut_len` (nearly every insert and copy) come from a table built
/// from the same scan at compile time: the scan per command was 2-3 % of
/// compression (perf, 2026-10-14).
fn lengthCode(comptime offsets: *const [24]u32, comptime nbits: *const [24]u5, len: u32) ?LenCode {
    const lut = comptime lengthLut(offsets, nbits);
    if (len < length_lut_len) {
        const i = lut[len];
        if (i == 0xff) return null;
        return .{ .code = @intCast(i), .extra = len - offsets[i], .nbits = nbits[i] };
    }
    return lengthCodeScan(offsets, nbits, len);
}

const LenCode = struct { code: u5, extra: u32, nbits: u5 };

/// `lengthCode` for `.q0`/`.q1` in one load: below `length_lut_len` an
/// entry packs the code (5 bits), its extra bit count (5) and its offset;
/// longer lengths take the scan. Never null for an insert or copy length
/// the parse makes (up to `max_match`, inserts up to a block).
inline fn packedLengthCode(comptime offsets: *const [24]u32, comptime nbits: *const [24]u5, len: u32) LenCode {
    const lut = comptime packedLengthLut(offsets, nbits);
    if (len < length_lut_len) {
        const e = lut[len];
        return .{ .code = @truncate(e), .nbits = @truncate(e >> 5), .extra = len - (e >> 10) };
    }
    return lengthCodeScan(offsets, nbits, len).?;
}

fn packedLengthLut(comptime offsets: *const [24]u32, comptime nbits: *const [24]u5) [length_lut_len]u32 {
    @setEvalBranchQuota(100_000);
    var t: [length_lut_len]u32 = undefined;
    for (&t, 0..) |*e, len| {
        // (Copy lengths 0 and 1 have no code; the parse never asks.)
        const c = lengthCodeScan(offsets, nbits, len) orelse {
            e.* = 0;
            continue;
        };
        e.* = @as(u32, c.code) | @as(u32, c.nbits) << 5 | offsets[c.code] << 10;
    }
    return t;
}

const length_lut_len = 1024;

fn lengthLut(comptime offsets: *const [24]u32, comptime nbits: *const [24]u5) [length_lut_len]u8 {
    @setEvalBranchQuota(100_000);
    var t: [length_lut_len]u8 = undefined;
    for (&t, 0..) |*e, len| e.* = if (lengthCodeScan(offsets, nbits, len)) |c| c.code else 0xff;
    return t;
}

fn lengthCodeScan(offsets: *const [24]u32, nbits: *const [24]u5, len: u32) ?LenCode {
    var i: usize = 24;
    while (i > 0) {
        i -= 1;
        if (len < offsets[i]) continue;
        const span: u64 = @as(u64, 1) << nbits[i];
        if (len - offsets[i] < span) return .{ .code = @intCast(i), .extra = len - offsets[i], .nbits = nbits[i] };
        return null; // beyond the top range
    }
    return null;
}

// ---------------------------------------------------------------------------
// Prefix codes: per-symbol bit patterns, already in stream (LSB-first) order.

const Code = struct {
    bits: []u16,
    len: []u8,

    fn deinit(self: *Code, gpa: std.mem.Allocator) void {
        gpa.free(self.bits);
        gpa.free(self.len);
        self.* = undefined;
    }

    fn emit(self: *const Code, w: *BitWriter, sym: usize) std.mem.Allocator.Error!void {
        try w.writeBits(self.bits[sym], @intCast(self.len[sym]));
    }
};

/// Invert a decoder-side `huffman.Table` into writable bit patterns.
///
/// A symbol with code length L ≤ `table.bits` occupies root indices
/// `rev + k * 2^L`; the smallest of those, `rev`, is exactly the L bits to
/// write (the reader peeks `table.bits` bits and indexes with them, so the
/// first bit written is the index's bit 0). A longer code sits in the subtable
/// a root link at index `i` points to, at `j + k * 2^(L - table.bits)`: its
/// bits are `i` then the smallest `j`. Deriving the patterns from the table the
/// *decoder* would build removes any chance of the two disagreeing about
/// canonical code assignment — the format-level risk is anchored externally
/// instead.
fn codeFromTable(gpa: std.mem.Allocator, table: *const huffman.Table, alphabet_size: u32) !Code {
    const bits = try gpa.alloc(u16, alphabet_size);
    errdefer gpa.free(bits);
    const len = try gpa.alloc(u8, alphabet_size);
    errdefer gpa.free(len);
    @memset(bits, 0);
    @memset(len, 0);

    const size = @as(usize, 1) << table.bits;
    for (table.entries[0..size], 0..) |e, i| {
        if (e.len & huffman.link_flag != 0) {
            const sub_size = @as(usize, 1) << @as(u5, @intCast(e.len & ~huffman.link_flag));
            for (table.entries[e.sym..][0..sub_size], 0..) |se, j| {
                if (se.sym >= alphabet_size) return error.InvalidHuffman;
                if (j < @as(usize, 1) << @as(u5, @intCast(se.len - table.bits))) {
                    bits[se.sym] = @intCast(i | (j << table.bits));
                    len[se.sym] = se.len;
                }
            }
            continue;
        }
        if (e.sym >= alphabet_size) return error.InvalidHuffman;
        if (e.len == 0) continue; // single-symbol code: nothing to write
        if (i < @as(usize, 1) << @as(u5, @intCast(e.len))) {
            bits[e.sym] = @intCast(i);
            len[e.sym] = e.len;
        }
    }
    return .{ .bits = bits, .len = len };
}

// ---------------------------------------------------------------------------
// Length-limited Huffman code lengths.

/// Assign canonical code lengths for `counts`, none longer than `limit`.
/// Symbols with count 0 get length 0. Returns the number of used symbols; when
/// that is 0 or 1 no lengths are written (a one-symbol alphabet cannot be
/// expressed as a *complex* code — its Kraft sum can never reach 1 — so the
/// caller must emit a simple code for it).
///
/// The depth limit is enforced by raising a *floor* under the counts and
/// rebuilding: once the floor exceeds every count all weights are equal and the
/// tree is balanced (depth `ceil(log2 m)`), which is <= 5 for the 18-symbol
/// code-length alphabet and <= 10 for the 704-symbol command alphabet. This is
/// a standard technique and always terminates.
fn assignLengths(
    gpa: std.mem.Allocator,
    counts: []const u32,
    limit: u5,
    lengths: []u8,
) std.mem.Allocator.Error!usize {
    @memset(lengths, 0);
    var m: usize = 0;
    for (counts) |c| {
        if (c != 0) m += 1;
    }
    if (m <= 1) return m;

    // Every alphabet but a large window's distances fits the stack.
    var stack: [max_stack_symbols]u64 = undefined;
    const keys = if (m <= max_stack_symbols) stack[0..m] else try gpa.alloc(u64, m);
    defer if (m > max_stack_symbols) gpa.free(keys);
    {
        var k: usize = 0;
        for (counts, 0..) |c, s| {
            if (c != 0) {
                keys[k] = @as(u64, c) << 32 | s;
                k += 1;
            }
        }
    }
    // Ascending by count, ties by symbol: the order a stable sort of the
    // symbols by count gives (a block sort through an index array until
    // 2026-10-15, 15 % of `.q1`'s cycles). max(count, floor) is monotone
    // in count, so this one order stays valid for every floor tried below.
    sortKeys(keys);

    const cap = 2 * m; // m leaves + (m - 1) internal nodes
    var wt_s: [2 * max_stack_symbols]u64 = undefined;
    var left_s: [2 * max_stack_symbols]u32 = undefined;
    var right_s: [2 * max_stack_symbols]u32 = undefined;
    var depth_s: [2 * max_stack_symbols]u8 = undefined;
    const big = m > max_stack_symbols;
    const wt = if (!big) wt_s[0..cap] else try gpa.alloc(u64, cap);
    defer if (big) gpa.free(wt);
    const left = if (!big) left_s[0..cap] else try gpa.alloc(u32, cap);
    defer if (big) gpa.free(left);
    const right = if (!big) right_s[0..cap] else try gpa.alloc(u32, cap);
    defer if (big) gpa.free(right);
    const depth = if (!big) depth_s[0..cap] else try gpa.alloc(u8, cap);
    defer if (big) gpa.free(depth);

    var floor: u64 = 1;
    while (true) : (floor *= 2) {
        for (keys, 0..) |k, i| wt[i] = @max(k >> 32, floor);

        // Two-queue Huffman: `a` walks the (sorted) leaves, `b` the internal
        // nodes, which are themselves produced in non-decreasing weight order.
        var a: usize = 0;
        var b: usize = m;
        var n: usize = m;
        while (n < 2 * m - 1) : (n += 1) {
            const c1 = pickMin(&a, &b, n, wt, m);
            const c2 = pickMin(&a, &b, n, wt, m);
            wt[n] = wt[c1] + wt[c2];
            left[n] = @intCast(c1);
            right[n] = @intCast(c2);
        }

        // A parent always has a higher index than its children, so a single
        // downward sweep propagates depths.
        const root = 2 * m - 2;
        depth[root] = 0;
        var i = root;
        while (i >= m) : (i -= 1) {
            const d = depth[i] + 1;
            depth[left[i]] = d;
            depth[right[i]] = d;
        }
        var maxd: u8 = 0;
        for (0..m) |j| maxd = @max(maxd, depth[j]);
        if (maxd <= limit) {
            for (keys, 0..) |k, j| lengths[@as(u32, @truncate(k))] = depth[j];
            return m;
        }
    }
}

/// Ascending sort of `keys` (google `SortHuffmanTreeItems`: insertion below
/// 13 items, Shell sort with gaps 132, 57, 23, 10, 4, 1 from there). Not
/// `std.sort.pdq`: its insertion pass swaps through byte stores here, and the
/// next 8-byte load of the same slot waits for them (store forwarding fails)
/// — a fifth of `.q6`'s cycles on a 16 KiB font (2026-10-16).
fn sortKeys(keys: []u64) void {
    const gaps = [_]usize{ 132, 57, 23, 10, 4, 1 };
    const first: usize = if (keys.len < 13) gaps.len - 1 else 0;
    for (gaps[first..]) |gap| {
        var i = gap;
        while (i < keys.len) : (i += 1) {
            const v = keys[i];
            var j = i;
            while (j >= gap and keys[j - gap] > v) : (j -= gap) keys[j] = keys[j - gap];
            keys[j] = v;
        }
    }
}

/// The largest alphabet `assignLengths` works on the stack for (the
/// command alphabet).
const max_stack_symbols = tables.num_command_symbols;

/// The bit patterns of the canonical code with `lengths` (RFC 7932 §3.2), in
/// stream order: what `codeFromTable` reads off the decoder's table for the
/// same lengths (`huffman.buildComplex`), computed without it (tested to
/// agree on random complete codes). A code that is not complete is
/// `error.EncoderInvariant`, as the table would refuse it.
fn canonicalCode(gpa: std.mem.Allocator, lengths: []const u8) GiveUp!Code {
    const bits = try gpa.alloc(u16, lengths.len);
    errdefer gpa.free(bits);
    try canonicalBits(lengths, bits);
    const len = try gpa.alloc(u8, lengths.len);
    @memcpy(len, lengths);
    return .{ .bits = bits, .len = len };
}

/// `canonicalCode`'s bit patterns into `bits` (`lengths.len` of them).
fn canonicalBits(lengths: []const u8, bits: []u16) GiveUp!void {
    var count = [_]u32{0} ** 16;
    for (lengths) |l| {
        if (l > 15) return error.EncoderInvariant;
        count[l] += 1;
    }
    count[0] = 0;
    var kraft: u32 = 0;
    for (count[1..], 1..) |c, l| kraft += c << @intCast(15 - l);
    if (kraft != 1 << 15) return error.EncoderInvariant;
    var next: [16]u32 = undefined;
    var code: u32 = 0;
    for (1..16) |l| {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    for (lengths, bits) |l, *b| {
        if (l == 0) {
            b.* = 0;
            continue;
        }
        const c = next[l];
        next[l] += 1;
        b.* = @intCast(@as(u32, @bitReverse(@as(u16, @intCast(c)))) >> @intCast(16 - @as(u5, @intCast(l))));
    }
}

/// Pick the cheaper of the next unused leaf and the next unused internal node.
/// Ties go to the leaf, which keeps the tree as shallow as possible — that is
/// what makes the equal-weight fallback in `assignLengths` balanced.
fn pickMin(a: *usize, b: *usize, n: usize, wt: []const u64, m: usize) usize {
    const have_leaf = a.* < m;
    const have_int = b.* < n;
    if (have_leaf and (!have_int or wt[a.*] <= wt[b.*])) {
        const r = a.*;
        a.* += 1;
        return r;
    }
    const r = b.*;
    b.* += 1;
    return r;
}

// ---------------------------------------------------------------------------
// Complex prefix code writer (RFC 7932 3.5) — the inverse of
// `Decoder.readComplexHuffman`.

/// One entry of the run-length-coded code-length stream: a code-length symbol
/// (0..17) plus its extra bits (only symbols 16 and 17 carry any).
const RleItem = struct { sym: u8, extra: u8, nextra: u3 };

/// Encode `n` (>= 3) repeats as a chain of `sym` (16 or 17) codes.
///
/// The decoder accumulates `repeat` as
/// `r_1 = d_1 + 3`, `r_j = (r_{j-1} - 2) << nextra + d_j + 3`,
/// so the deltas fall out by inverting that recurrence — which produces them
/// last-to-first, hence the reversal on the way out.
fn emitRepeatChain(
    gpa: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(RleItem),
    sym: u8,
    nextra: u3,
    n: usize,
) std.mem.Allocator.Error!void {
    std.debug.assert(n >= 3);
    var deltas: [32]u8 = undefined;
    var k: usize = 0;
    var cur = n;
    const mask: usize = (@as(usize, 1) << nextra) - 1;
    while (true) {
        const m = cur - 3;
        deltas[k] = @intCast(m & mask);
        k += 1;
        const m2 = m >> nextra;
        if (m2 == 0) break;
        cur = m2 + 2;
    }
    while (k > 0) {
        k -= 1;
        try out.append(gpa, .{ .sym = sym, .extra = deltas[k], .nextra = nextra });
    }
}

/// Run-length-code `lengths` into the code-length symbol stream, stopping after
/// the last non-zero length (the decoder's own loop stops there too, because
/// its Kraft budget `space2` hits zero exactly then).
fn rleCodeLengths(
    gpa: std.mem.Allocator,
    lengths: []const u8,
    out: *std.ArrayListUnmanaged(RleItem),
) std.mem.Allocator.Error!void {
    var last: usize = 0;
    var any = false;
    for (lengths, 0..) |l, i| {
        if (l != 0) {
            last = i;
            any = true;
        }
    }
    if (!any) return;

    var i: usize = 0;
    while (i <= last) {
        const v = lengths[i];
        var j = i;
        while (j <= last and lengths[j] == v) j += 1;
        var run = j - i;
        if (v == 0) {
            // REPEAT_ZERO (17) needs no preceding literal.
            if (run < 3) {
                for (0..run) |_| try out.append(gpa, .{ .sym = 0, .extra = 0, .nextra = 0 });
            } else {
                try emitRepeatChain(gpa, out, tables.repeat_zero_code_length, 3, run);
            }
        } else {
            // REPEAT_PREVIOUS (16) copies `prev_code_len`, which is only set by
            // an actual literal length, so the first of a run is always literal.
            try out.append(gpa, .{ .sym = v, .extra = 0, .nextra = 0 });
            run -= 1;
            if (run >= 3) {
                try emitRepeatChain(gpa, out, tables.repeat_previous_code_length, 2, run);
            } else {
                for (0..run) |_| try out.append(gpa, .{ .sym = v, .extra = 0, .nextra = 0 });
            }
        }
        i = j;
    }
}

/// Write a complex prefix code for `lengths` (HSKIP = 0). `lengths` must be a
/// complete code over at least two symbols.
fn writeComplexCode(gpa: std.mem.Allocator, w: *BitWriter, lengths: []const u8) GiveUp!void {
    // A run of n lengths becomes at most n items, so they fit a buffer of
    // the largest alphabet: `append` never allocates.
    var item_buf: [max_rle_alphabet]RleItem = undefined;
    if (lengths.len > item_buf.len) return error.EncoderInvariant;
    var items: std.ArrayListUnmanaged(RleItem) = .initBuffer(&item_buf);
    try rleCodeLengths(gpa, lengths, &items);
    if (items.items.len == 0) return error.EncoderInvariant;

    var counts = [_]u32{0} ** tables.code_length_codes;
    for (items.items) |it| counts[it.sym] += 1;

    var cl_lengths = [_]u8{0} ** tables.code_length_codes;
    const m = try assignLengths(gpa, &counts, 5, &cl_lengths);
    if (m == 0) return error.EncoderInvariant;
    if (m == 1) {
        // A one-symbol code-length code is legal (the decoder accepts
        // `num_codes == 1` without a complete Kraft sum) and costs zero bits
        // per symbol. `assignLengths` leaves it to us to pick the length.
        for (counts, 0..) |c, s| {
            if (c != 0) cl_lengths[s] = 1;
        }
    }

    // The code-length code's patterns, computed rather than read off a
    // decoder table (`canonicalCode`; that table and the items' allocation
    // were half of this function's time on a 16 KiB font, 2026-10-16). A
    // one-symbol code writes no bits for its symbol.
    var cl_bits: [tables.code_length_codes]u16 = @splat(0);
    var cl_emit: [tables.code_length_codes]u8 = @splat(0);
    if (m != 1) {
        try canonicalBits(&cl_lengths, &cl_bits);
        cl_emit = cl_lengths;
    }

    // Header: HSKIP = 0, then the code-length code's own lengths in
    // `code_length_code_order`, using the fixed prefix code. The decoder stops
    // reading as soon as its Kraft budget is exhausted, so we must stop writing
    // at exactly the same point.
    try w.writeBits(0, 2);
    var space: i32 = 32;
    var num_codes: u32 = 0;
    var written: usize = 0;
    for (tables.code_length_code_order) |idx| {
        const v = cl_lengths[idx];
        // The fixed prefix code of RFC 7932 3.5 only encodes lengths 0..5.
        if (v >= cl_prefix.len) return error.EncoderInvariant;
        const p = cl_prefix[v];
        try w.writeBits(p.bits, p.len);
        written += 1;
        if (v != 0) {
            space -= @as(i32, 32) >> @intCast(v);
            num_codes += 1;
            if (space <= 0) break;
        }
    }
    if (!(num_codes == 1 or space == 0)) return error.EncoderInvariant;
    // Anything the decoder will not read must have been zero anyway.
    for (tables.code_length_code_order[written..]) |idx| {
        if (cl_lengths[idx] != 0) return error.EncoderInvariant;
    }

    for (items.items) |it| {
        if (cl_lengths[it.sym] == 0) return error.EncoderInvariant;
        try w.writeBits(cl_bits[it.sym], @intCast(cl_emit[it.sym]));
        if (it.nextra != 0) try w.writeBits(it.extra, it.nextra);
    }
}

/// Write a simple prefix code (RFC 7932 3.4) over 1..4 symbols.
fn writeSimpleCode(w: *BitWriter, alphabet_size: u32, vals: []const u16, tree_select: u1) GiveUp!void {
    if (vals.len == 0 or vals.len > 4) return error.EncoderInvariant;
    const max_bits = huffman.symbolBits(alphabet_size - 1);
    try w.writeBits(1, 2); // kind = 1 => simple
    try w.writeBits(@intCast(vals.len - 1), 2);
    for (vals) |v| {
        if (v >= alphabet_size) return error.EncoderInvariant;
        try w.writeBits(v, max_bits);
    }
    if (vals.len == 4) try w.writeBits(tree_select, 1);
}

/// Build the prefix code for `counts`, write its header, and return the
/// writable bit patterns. `counts` must have at least one non-zero entry.
fn buildAndWriteCode(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    counts: []const u32,
    alphabet_size: u32,
) GiveUp!Code {
    return buildAndWriteCodeWide(gpa, w, counts, alphabet_size, alphabet_size);
}

/// `buildAndWriteCode` where a simple code's symbols are as wide as for an
/// alphabet of `simple_alphabet` (a large window's distances: read as from
/// the 62-bit alphabet, only `alphabet_size` of them valid).
fn buildAndWriteCodeWide(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    counts: []const u32,
    alphabet_size: u32,
    simple_alphabet: u32,
) GiveUp!Code {
    return buildAndWriteCodeLimited(gpa, w, counts, alphabet_size, simple_alphabet, tables.max_code_length);
}

/// `buildAndWriteCodeWide` with the code lengths taken from `counts`
/// smoothed for a run-length coded header (`optimizeCountsForRle`): a
/// meta-block's literal, command and distance codes, as google/brotli builds
/// them from quality 4 on (`BrotliOptimizeHistograms`). The symbols are
/// still priced by their real counts.
fn buildAndWriteCodeRle(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    counts: []const u32,
    alphabet_size: u32,
    simple_alphabet: u32,
) GiveUp!Code {
    var buf: [max_rle_alphabet]u32 = undefined;
    const smooth = buf[0..counts.len];
    @memcpy(smooth, counts);
    optimizeCountsForRle(smooth);
    return buildAndWriteCodeWide(gpa, w, smooth, alphabet_size, simple_alphabet);
}

const max_rle_alphabet = @max(tables.num_command_symbols, dist_alphabet_max);

/// Make `counts` give code lengths that run-length code shorter: runs of
/// counts that are close are replaced by their mean, isolated zeros among
/// small counts become ones. A port of google/brotli 1.2.0's
/// `BrotliOptimizeHuffmanCountsForRle` (`c/enc/entropy_encode.c`, MIT, see
/// `NOTICE`), its 24.8 fixed point included. A used symbol keeps a non-zero
/// count. On a 64 KiB font at `.q6` the code headers were 2.4 KB without it,
/// google's 0.7 KB (2026-10-16).
fn optimizeCountsForRle(counts: []u32) void {
    const streak_limit: u64 = 1240;
    var nonzeros: usize = 0;
    var smallest: u32 = 1 << 30;
    for (counts) |c| {
        if (c == 0) continue;
        nonzeros += 1;
        smallest = @min(smallest, c);
    }
    // Small histograms are modelled well as they are.
    if (nonzeros < 16) return;
    var length = counts.len;
    while (counts[length - 1] == 0) length -= 1;
    if (smallest < 4 and length - nonzeros < 6) {
        for (1..length - 1) |i| {
            if (counts[i - 1] != 0 and counts[i] == 0 and counts[i + 1] != 0) counts[i] = 1;
        }
    }
    if (nonzeros < 28) return;

    // Runs that already code well (five zeros or seven equal non-zeros on)
    // are kept as they are.
    var good: [max_rle_alphabet]bool = undefined;
    @memset(good[0..length], false);
    {
        var symbol = counts[0];
        var step: usize = 0;
        for (0..length + 1) |i| {
            if (i == length or counts[i] != symbol) {
                if ((symbol == 0 and step >= 5) or (symbol != 0 and step >= 7)) {
                    @memset(good[i - step .. i], true);
                }
                step = 1;
                if (i != length) symbol = counts[i];
            } else {
                step += 1;
            }
        }
    }

    // A stride of counts within `streak_limit` (24.8) of its running mean
    // becomes that mean.
    var stride: u64 = 0;
    var limit: u64 = 256 * (@as(u64, counts[0]) + counts[1] + counts[2]) / 3 + 420;
    var sum: u64 = 0;
    for (0..length + 1) |i| {
        if (i == length or good[i] or (i != 0 and good[i - 1]) or
            (256 * @as(u64, counts[i]) -% limit +% streak_limit) >= 2 * streak_limit)
        {
            if (stride >= 4 or (stride >= 3 and sum == 0)) {
                // An all-zero stride stays zero.
                const mean: u32 = if (sum == 0) 0 else @intCast(@max(1, (sum + stride / 2) / stride));
                // `counts[i]` already belongs to the next stride.
                @memset(counts[i - @as(usize, @intCast(stride)) .. i], mean);
            }
            stride = 0;
            sum = 0;
            if (i + 2 < length) {
                limit = 256 * (@as(u64, counts[i]) + counts[i + 1] + counts[i + 2]) / 3 + 420;
            } else if (i < length) {
                limit = 256 * @as(u64, counts[i]);
            } else {
                limit = 0;
            }
        }
        stride += 1;
        if (i != length) {
            sum += counts[i];
            if (stride >= 4) limit = (256 * sum + stride / 2) / stride;
            if (stride == 4) limit += 120;
        }
    }
}

/// `buildAndWriteCodeWide` with codes of at most `limit` bits.
fn buildAndWriteCodeLimited(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    counts: []const u32,
    alphabet_size: u32,
    simple_alphabet: u32,
    limit: u5,
) GiveUp!Code {
    var used: [4]u16 = undefined;
    var m: usize = 0;
    for (counts, 0..) |c, s| {
        if (c == 0) continue;
        if (m < 4) used[m] = @intCast(s);
        m += 1;
    }
    if (m == 0) return error.EncoderInvariant;

    if (m <= 4) {
        // Simple codes: far cheaper than an 18-entry complex header, and the
        // only legal encoding at all when m == 1.
        var vals: [4]u16 = undefined;
        @memcpy(vals[0..m], used[0..m]);
        // Descending frequency. Only `vals[0]`'s position is load-bearing: the
        // 3-symbol and skewed 4-symbol shapes give it the shortest code. Within
        // an equal-length group the order does NOT matter, because
        // `huffman.buildSimple` normalises it identically on both sides — so
        // sorting those here would be dead code, not a safety net.
        std.mem.sort(u16, vals[0..m], counts, struct {
            fn gt(cs: []const u32, a: u16, b: u16) bool {
                return cs[a] > cs[b];
            }
        }.gt);

        var tree_select: u1 = 0;
        if (m == 4) {
            // {2,2,2,2} versus {1,2,3,3}; pick whichever prices these counts lower.
            const c: [4]u64 = .{ counts[vals[0]], counts[vals[1]], counts[vals[2]], counts[vals[3]] };
            const flat = 2 * (c[0] + c[1] + c[2] + c[3]);
            const skew = c[0] + 2 * c[1] + 3 * c[2] + 3 * c[3];
            if (skew < flat) tree_select = 1;
        }
        try writeSimpleCode(w, simple_alphabet, vals[0..m], tree_select);
        const num_symbols: u8 = @intCast(m - 1 + @as(usize, if (m == 4) tree_select else 0));
        var table = try huffman.buildSimple(gpa, num_symbols, vals[0..m]);
        defer table.deinit(gpa);
        return codeFromTable(gpa, &table, alphabet_size);
    }

    const lengths = try gpa.alloc(u8, alphabet_size);
    defer gpa.free(lengths);
    _ = try assignLengths(gpa, counts, limit, lengths);
    try writeComplexCode(gpa, w, lengths);
    return canonicalCode(gpa, lengths);
}

// ---------------------------------------------------------------------------
// Match finding: bucketed hash over 4-byte hashes, one lazy step.
//
// Each hash bucket keeps the last `depth` positions inserted under it, in a
// ring of `depth` slots. Until 2026-10-14 this was a hash chain (`head` per
// hash, `prev` per position), walking up to `depth` links: every link is a
// load whose address is the previous load's value, so the walk was a chain of
// dependent cache accesses — half of `find`'s cycles waited on `prev[c]` and
// on the candidate byte that depends on it (perf, `.q6` on text). A
// bucket names all its candidates at once, so their loads overlap.

/// `word`: 0 for a copy; for a static-dictionary word (`Matcher.findWord`)
/// its length, `len` then the bytes its transformed form produces. `len`
/// and `word` share a word (`max_match` fits 16 bits): at 16 bytes a `?Match`
/// is no longer returned in registers, and `.q9` on text was 16 % slower
/// (2026-10-15).
const Match = struct { len: u16, word: u8 = 0, dist: u32, gain: f32 };

/// Distances an explicit distance code reaches (NPOSTFIX = NDIRECT = 0):
/// the last code's offset plus its 24 extra bits.
const max_code_distance = (1 << 26) - 4;
/// A position no copy can come from (`shift` marks dropped ones with it):
/// never below the position searched.
const dropped_pos = std.math.maxInt(u32);

/// What came before `data[0]`: output a stream dropped (`StreamWriter`'s
/// history slid). A raw prefix dictionary is not in `data`: it is searched
/// in its own table (`PreparedDictionary`, `searchDictionary`).
const History = struct {
    dropped: usize = 0,

    /// How far back the output reaches from `p`: the window, or what was
    /// produced so far.
    fn outMax(x: History, p: usize, max_dist: usize) usize {
        return @min(max_dist, p + x.dropped);
    }

    /// Positions move down by `by`, or become `dropped_pos` when they fall
    /// off.
    fn shiftPos(s: u32, by: u32) u32 {
        if (s == dropped_pos) return s;
        return if (s < by) dropped_pos else s - by;
    }
};

/// A raw prefix dictionary (RFC 9841 §3.2) as the match finders see it: its
/// table (`PreparedDictionary`), searched beside their own at every lookup,
/// as google/brotli searches a compound dictionary (`hash.h`,
/// `FindCompoundDictionaryMatch`, MIT, see `NOTICE`). The decoder names its
/// byte `o` from `out_max` (how far back the output reaches) by the
/// distance `out_max + source.len - o`; a copy from it ends at its end
/// (google's too: RFC 9841 lets one run on into the output, which only
/// helps a copy that starts within a few bytes of the dictionary's end).
const DictRef = struct {
    pd: *const PreparedDictionary,

    /// The longest copy for `p` from the dictionary that saves more than
    /// `best.gain` (`Matcher.gain`'s estimate at `lit_cost`), into `best`:
    /// first at the ring's distances that reach past the output, then
    /// along the bucket of `p`'s five bytes. `out_max`: as `History.outMax`;
    /// `max_len`: the longest copy the block allows; `ring_n` of the ring
    /// tried (as `Matcher.find`); `max_items`: how many of the bucket's
    /// positions, newest first.
    inline fn search(r: DictRef, comptime max_items: u32, data: []const u8, p: usize, out_max: usize, max_len: usize, lit_cost: f32, ring: []const u32, best: *Best) void {
        const src = r.pd.source;
        const top = out_max + src.len; // the distance of the dictionary's byte 0
        for (ring, 0..) |rd, i| {
            const d: usize = rd;
            if (d <= out_max or d > top) continue;
            const o = top - d;
            const l = matchLenAt(src[o..].ptr, data[p..].ptr, @min(max_len, src.len - o));
            if (l < @as(usize, if (i < 2) min_ring_match else 3)) continue;
            const g = @as(f32, @floatFromInt(l)) * lit_cost - @as(f32, if (i == 0) 3 else 5);
            if (g > best.gain) best.* = .{ .len = l, .dist = d, .gain = g };
        }
        if (p + PreparedDictionary.read_len > data.len) return;
        var ch = r.pd.chain(data[p..][0..PreparedDictionary.read_len]);
        var walked: u32 = 0;
        while (ch.next()) |o32| : (walked += 1) {
            if (walked == max_items) break;
            const o: usize = o32;
            const d = top - o;
            if (d > max_code_distance) continue;
            const cap = @min(max_len, src.len - o);
            // google: copies of at least 4 bytes, so the four bytes that
            // end one past the best length are compared before anything.
            const bl = @max(best.len, 3);
            if (bl >= cap) continue;
            if (std.mem.readInt(u32, data[p + bl - 3 ..][0..4], .little) != std.mem.readInt(u32, src[o + bl - 3 ..][0..4], .little)) continue;
            const l = matchLenAt(src[o..].ptr, data[p..].ptr, cap);
            if (l < min_match) continue;
            const dist_bits: f32 = @floatFromInt(std.math.log2_int(usize, d));
            const g = @as(f32, @floatFromInt(l)) * lit_cost - dist_bits - 6;
            if (g > best.gain) best.* = .{ .len = l, .dist = d, .gain = g };
        }
    }

    /// `Matcher.collect`'s candidates from the dictionary: copies longer
    /// than `best_len` and than each before (google
    /// `FindAllCompoundDictionaryMatches`), appended to `out[found..]`;
    /// returns the new count.
    inline fn collect(r: DictRef, data: []const u8, p: usize, out_max: usize, max_len: usize, best_len_in: usize, out: *[max_cands]Cand, found_in: usize) usize {
        if (p + PreparedDictionary.read_len > data.len) return found_in;
        const src = r.pd.source;
        const top = out_max + src.len;
        var found = found_in;
        var best_len = @max(best_len_in, min_match - 1);
        var ch = r.pd.chain(data[p..][0..PreparedDictionary.read_len]);
        while (ch.next()) |o32| {
            if (found == max_cands) break;
            const o: usize = o32;
            const d = top - o;
            if (d > max_code_distance) continue;
            const cap = @min(max_len, src.len - o);
            if (best_len >= cap or data[p + best_len] != src[o + best_len]) continue;
            const l = matchLenAt(src[o..].ptr, data[p..].ptr, cap);
            if (l > best_len) {
                best_len = l;
                out[found] = .{ .len = @intCast(l), .dist = @intCast(d) };
                found += 1;
            }
        }
        return found;
    }
};

/// The best copy a search found so far: `Match` without the word.
const Best = struct { len: usize = 0, dist: usize = 0, gain: f32 = 0 };

/// Length of the common prefix of `a[0..]` and `b[0..]`, at most `max_len`
/// (both readable that far): eight bytes per step, the first differing byte
/// from the XOR's trailing zeros.
inline fn matchLenAt(a: [*]const u8, b: [*]const u8, max_len: usize) usize {
    var l: usize = 0;
    while (l + 8 <= max_len) : (l += 8) {
        const x = std.mem.readInt(u64, a[l..][0..8], .little) ^ std.mem.readInt(u64, b[l..][0..8], .little);
        if (x != 0) return l + @ctz(x) / 8;
    }
    while (l < max_len and a[l] == b[l]) l += 1;
    return l;
}

/// log2 of a match finder's buckets for an input of `size` bytes: 2^8 at
/// least, one per byte up to 2^`max` — compressing a few hundred bytes must
/// not cost a fixed table.
fn bucketLog(size: usize, max: u6) u6 {
    var b: u6 = 8;
    while (b < max and std.math.shl(usize, 1, b) < size) b += 1;
    return b;
}

/// The transforms that cut 0..9 bytes off a word's end and add nothing
/// (RFC 7932 Appendix B: identity, OMIT_LAST_1..9).
const omit_last_transforms = [10]u8{ 0, 12, 27, 23, 42, 63, 56, 48, 59, 64 };

/// Slots per bucket of `.q6`'s `Matcher`: one vector compare of the tags.
const simd_depth = 32;

/// The deep match finder (`.q6`, `.q9`, `.q11`). `wide`: google/brotli's
/// hasher for large inputs (H6, and H68 at q5–q7: `hash_longest_match64_inc.h`,
/// MIT, see `NOTICE`) — five bytes hashed (`kHashMul64`) into 2^15 buckets, for
/// an input known to be 1 MiB or more with a window of 19 bits or more
/// (`Core.wideFor`); else four bytes into a table sized to the input
/// (`Effort.slotsLog`).
fn MatcherT(comptime wide: bool) type {
    return struct {
        const Self = @This();
        /// The tag bits of a slot.
        const tagged_mask: u32 = 0xff00_0000;
        /// Data a tagged slot can index: positions below this, which is itself
        /// a dropped position (`dropped_pos` with its tag bits).
        const tagged_limit: u32 = 0x00ff_ffff;

        /// Slots per bucket = candidates walked per lookup (`Effort.depth`), a
        /// power of two.
        depth: u32,
        /// `count` then `slots` (`initIn`).
        mem: []u32,
        /// Estimated bits a literal costs in the current block (its order-0
        /// entropy): what a match saves per byte it covers. Set per block.
        lit_cost: f32 = 8,
        /// `depth` slots per bucket, positions. A slot is read only when the
        /// bucket's count says it was written.
        ///
        /// While every position fits in 24 bits (`tag_mask` set), a slot's top
        /// eight bits are a tag: eight more bits of its position's hash
        /// (`Hashed.tag`). A lookup in a binary block (`tagsPay`) skips a
        /// slot whose tag is not its own without loading anything from the
        /// data: there a bucket mostly holds positions that merely share its
        /// hash bits, and each of those cost a load from far back — on a font,
        /// 66 slots visited per lookup at `.q9`, 11 with the same first four
        /// bytes (2026-10-15). A different tag means different first four
        /// bytes, so no copy is missed. (Tags in a byte array of their own cost
        /// text 4–7 % in the extra cache line.)
        slots: []u32,
        /// `tagged_mask` while positions are tagged, else 0 (`setData`).
        tag_mask: u32 = tagged_mask,
        /// Positions ever inserted per bucket (the next slot is `count % depth`).
        count: []u32,
        depth_log: u5,
        hash_shift: u5,
        data: []const u8,
        /// The decoder's last four distances as the commands so far leave them
        /// (`buildCommands` keeps it): a copy at one of them is named by a short
        /// code with no extra bits, so it is tried first and priced lower.
        ring: DistRing = .{},
        history: History = .{},
        /// A prefix dictionary, searched beside the slots (`DictRef`).
        dict: ?DictRef = null,
        /// Its length (0 without): static-dictionary words count past it.
        dict_len: usize = 0,
        /// `findWord`'s buckets looked at and words taken: it stops looking
        /// while fewer than one lookup in 128 found a word (google/brotli
        /// `SearchInStaticDictionary`) — binary data never does.
        dict_lookups: usize = 0,
        dict_matches: usize = 0,

        /// Tables of 2^`slots_log` slots in all (`Effort.slotsLog`), `depth`
        /// per bucket; `data` is set by the caller. Freed by `deinit`.
        fn init(gpa: std.mem.Allocator, depth: u32, slots_log: u5) std.mem.Allocator.Error!Self {
            return initIn(try gpa.alloc(u32, tableLen(depth, slots_log)), depth, slots_log);
        }

        /// The `u32`s of `init`'s tables.
        fn tableLen(depth: u32, slots_log: u5) usize {
            const bucket_log = bucketLogFor(depth, slots_log);
            return (@as(usize, 1) << @intCast(bucket_log)) + (@as(usize, 1) << @intCast(bucket_log + std.math.log2_int(u32, depth)));
        }

        /// As `init`, the tables in `mem` (at least `tableLen` long, its
        /// contents anything): what `init` makes, on memory kept between
        /// inputs (`Core.reinit`).
        fn initIn(mem: []u32, depth: u32, slots_log: u5) Self {
            std.debug.assert(std.math.isPowerOfTwo(depth));
            const depth_log: u5 = @intCast(std.math.log2_int(u32, depth));
            const bucket_log: u5 = @intCast(bucketLogFor(depth, slots_log));
            const n_count = @as(usize, 1) << bucket_log;
            const count = mem[0..n_count];
            // `slots` is left as it was: only the slots a bucket's count
            // covers are read, and each was written first.
            const slots = mem[n_count..][0 .. @as(usize, 1) << (bucket_log + depth_log)];
            fillZero(count);
            return .{
                .depth = depth,
                .mem = mem,
                .slots = slots,
                .count = count,
                .depth_log = depth_log,
                .hash_shift = @intCast(32 - @as(u6, bucket_log)),
                .data = &.{},
            };
        }

        /// log2 of the buckets `init` makes: 2^8 at least.
        fn bucketLogFor(depth: u32, slots_log: u5) u6 {
            return @intCast(@max(8, @as(i8, slots_log) - std.math.log2_int(u32, depth)));
        }

        /// `@memset(buf, 0)` in 32-byte stores. Zig 0.16 without libc lowers
        /// `@memset` to `compiler_rt.memset`, which stores one byte at a time:
        /// 20 % of `fast` compression of 128 KiB (bench 2026-10-11). The stores
        /// are volatile so LLVM does not turn the loop back into that call. Same
        /// workaround as `zstd/src/fill.zig`; `fastmem` exports a replacement for
        /// whole executables. Delete when Zig's memset is vectorised (after 0.16)
        /// and go back to `@memset`.
        fn fillZero(buf: []u32) void {
            const V = @Vector(8, u32);
            const v: V = @splat(0);
            const p: [*]volatile u32 = buf.ptr;
            var i: usize = 0;
            while (i + 8 <= buf.len) : (i += 8) {
                const w: *align(4) volatile V = @ptrCast(p + i);
                w.* = v;
            }
            while (i < buf.len) : (i += 1) p[i] = 0;
        }

        /// Length of the common prefix of `data[c..]` and `data[p..]`, at most
        /// `max_len` (`p + max_len <= data.len`, `c < p`): eight bytes per step,
        /// the first differing byte from the XOR's trailing zeros.
        fn matchLen(data: []const u8, c: usize, p: usize, max_len: usize) usize {
            var l: usize = 0;
            while (l + 8 <= max_len) : (l += 8) {
                const x = std.mem.readInt(u64, data[c + l ..][0..8], .little) ^ std.mem.readInt(u64, data[p + l ..][0..8], .little);
                if (x != 0) return l + @ctz(x) / 8;
            }
            while (l < max_len and data[c + l] == data[p + l]) l += 1;
            return l;
        }

        /// After `init` (not `initIn`).
        fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            gpa.free(self.mem);
            self.* = undefined;
        }

        /// Empty, as `init` leaves it.
        fn reset(self: *Self) void {
            fillZero(self.count);
            self.ring = .{};
            self.dict_lookups = 0;
            self.dict_matches = 0;
        }

        /// `by` output bytes left `data` (`History.shiftPos`). Only the slots a
        /// count covers hold positions; the rest are shifted as garbage.
        fn shift(self: *Self, by: u32) void {
            const m = self.tag_mask;
            for (self.slots) |*s| {
                const pos = s.* & ~m;
                const moved = History.shiftPos(if (pos == ~m) dropped_pos else pos, by);
                s.* = if (moved == dropped_pos) dropped_pos else moved | (s.* & m);
            }
            self.history.dropped += by;
        }

        /// The data positions index. Past `tagged_limit` bytes the slots lose
        /// their tags, once.
        fn setData(self: *Self, data: []const u8) void {
            self.data = data;
            if (self.tag_mask == 0 or data.len < tagged_limit) return;
            for (self.slots) |*s| s.* = if (s.* & ~tagged_mask == tagged_limit) dropped_pos else s.* & ~tagged_mask;
            self.tag_mask = 0;
        }

        /// The bytes `hash` reads at a position.
        const hash_len: usize = if (wide) 5 else min_match;

        /// The `hash_len` bytes at `p` hashed: the bucket from the top bits,
        /// a slot's tag bits (`slots`) from the eight below them.
        const Hashed = struct { bucket: usize, tag: u32 };

        fn hash(self: *const Self, p: usize) Hashed {
            if (wide) {
                // google `HashBytes` (H6): `load64 * (kHashMul64 << 24)`, of
                // which only the low five bytes reach the top bits.
                const v = @as(u64, std.mem.readInt(u32, self.data[p..][0..4], .little)) | @as(u64, self.data[p + 4]) << 32;
                const x = (v << 24) *% 0x1FE35A7B_D3579BD3;
                const bucket_log: u6 = 32 - @as(u6, self.hash_shift);
                return .{
                    .bucket = @intCast(x >> @intCast(64 - @as(u7, bucket_log))),
                    .tag = @as(u32, @truncate((x << bucket_log) >> 32)) & self.tag_mask,
                };
            }
            const x = std.mem.readInt(u32, self.data[p..][0..4], .little) *% 0x1e35a7bd;
            return .{ .bucket = x >> self.hash_shift, .tag = (x << @intCast(32 - @as(u6, self.hash_shift))) & self.tag_mask };
        }

        /// Start loading the bucket `p` hashes to: positions are visited in
        /// order, so the next lookup's bucket can be on its way while this one
        /// is compared.
        fn prefetch(self: *const Self, p: usize) void {
            if (p + hash_len > self.data.len) return;
            const h = self.hash(p).bucket;
            @prefetch(&self.count[h], .{});
            @prefetch(&self.slots[h << self.depth_log], .{});
        }

        fn insert(self: *Self, p: usize) void {
            if (p + hash_len > self.data.len) return;
            const hv = self.hash(p);
            const h = hv.bucket;
            const n = self.count[h];
            self.slots[(h << self.depth_log) | (n & (self.depth - 1))] = @as(u32, @intCast(p)) | hv.tag;
            self.count[h] = n +% 1;
        }

        /// The match's estimated saving in bits: the literals it replaces minus
        /// what naming it costs — the distance's extra bits (about log2 of it)
        /// and a few bits of command and distance symbol. On text a literal costs
        /// 4-5 bits and nearly every match pays; on random bytes over a small
        /// alphabet a literal costs 2-3 and a far, short match loses (measured:
        /// `alpha5_flat` 10 417 bytes with the longest match taken, worse the
        /// deeper the search looked, against ~9 000 for no matches at all).
        fn gain(self: *const Self, len: usize, dist: usize) f32 {
            const dist_bits: f32 = @floatFromInt(std.math.log2_int(usize, dist));
            return @as(f32, @floatFromInt(len)) * self.lit_cost - dist_bits - 6;
        }

        /// The match for `p` that saves the most bits (`gain`), ending at or
        /// before `limit`, at most `max_dist` back. Null below `min_match` or
        /// when no candidate saves anything.
        /// `ring_n`: how many of the ring's distances are tried first (all four
        /// since the ring was fixed, 2026-10-15: fonts −0.3 %, text even).
        /// Comptime, so a search
        /// without them compiles to the loop it was before they existed.
        /// `px`: a prefix dictionary is attached (`dict`) — comptime, so a
        /// search without one compiles to the loop it was before dictionaries
        /// (the per-candidate test cost `.q9` 20 %, measured 2026-10-15).
        /// `tagged`: skip slots by their tag (`slots`) — comptime, as a mask
        /// test in the one loop cost text 25 % in the registers it took
        /// (2026-10-15); the caller picks per block (`tagsPay`).
        /// `simd` (`.q6`, 32 slots a bucket): with `tagged`, the bucket's tags
        /// are compared at once and only the slots whose tag is the position's
        /// own are visited, as google/brotli's H58 hasher does with tag bytes of
        /// their own (`hash_longest_match_simd_inc.h`; a byte array here cost
        /// text 7 % in the extra stores, 2026-10-15).
        /// `align(64)` (also `findWord`, `buildCommands`): where the hot loops
        /// start otherwise moves with every unrelated change, and on the
        /// measuring host (a Kaby Lake, which pays for jumps across 32-byte
        /// lines) that alone moved `.q6` by 5–10 % between builds; aligned, the
        /// bench of the unchanged encoder was 3–10 % faster (2026-10-15).
        fn find(self: *const Self, comptime ring_n: u3, comptime px: bool, comptime tagged: bool, comptime simd: bool, p: usize, max_dist: usize, limit: usize) align(64) ?Match {
            if (p + hash_len > limit) return null;
            const max_len = @min(limit - p, max_match);
            const own = self.findOwn(ring_n, tagged, simd, p, max_dist, max_len);
            if (!px) return own;
            var best: Best = if (own) |m| .{ .len = m.len, .dist = m.dist, .gain = m.gain } else .{};
            if (best.len < max_len) self.dict.?.search(std.math.maxInt(u32), self.data, p, max_dist, max_len, self.lit_cost, self.ring.last[0..ring_n], &best);
            if (best.len == 0) return null;
            return .{ .len = @intCast(best.len), .dist = @intCast(best.dist), .gain = best.gain };
        }

        /// `find` in the data's own positions.
        inline fn findOwn(self: *const Self, comptime ring_n: u3, comptime tagged: bool, comptime simd: bool, p: usize, max_dist: usize, max_len: usize) ?Match {
            var best_len: usize = 0;
            var best_dist: usize = 0;
            var best_gain: f32 = 0;
            if (ring_n != 0) {
                const head2 = std.mem.readInt(u32, self.data[p..][0..4], .little) & 0xffff;
                for (self.ring.last[0..ring_n], 0..) |rd, i| {
                    const d: usize = rd;
                    if (d == 0 or d > max_dist) continue;
                    const c = p - d;
                    // Most fail on the first bytes: no full compare for those.
                    if (std.mem.readInt(u32, self.data[c..][0..4], .little) & 0xffff != head2) continue;
                    const l = matchLen(self.data, c, p, max_len);
                    if (l < @as(usize, if (i < 2) min_ring_match else 3)) continue;
                    // The last distance: code 0 or no distance symbol at all; the
                    // second-last: a two-bit-ish short code.
                    const g = @as(f32, @floatFromInt(l)) * self.lit_cost - @as(f32, if (i == 0) 3 else 5);
                    if (g > best_gain) {
                        best_gain = g;
                        best_len = l;
                        best_dist = d;
                    }
                }
            }
            if (ring_n != 0 and best_len >= max_len) return .{ .len = @intCast(best_len), .dist = @intCast(best_dist), .gain = best_gain };
            const hv = self.hash(p);
            const h = hv.bucket;
            const n = self.count[h];
            // Newest first; a wrapped count still means a full bucket.
            const valid = if (n < self.depth) n else self.depth;
            const bucket = self.slots[h << self.depth_log ..][0..self.depth];
            const m = if (tagged) tagged_mask else self.tag_mask;
            if (simd and tagged) {
                // Bit k of `mask`: the k-th newest slot, `n - 1 - k`.
                const V = @Vector(simd_depth, u32);
                const sv: V = bucket[0..simd_depth].*;
                const eq = (sv & @as(V, @splat(tagged_mask))) == @as(V, @splat(hv.tag));
                const by_slot: u32 = @bitCast(eq);
                var mask = std.math.rotr(u32, @bitReverse(by_slot), @as(u5, @truncate(0 -% n)));
                if (n < simd_depth) mask &= (@as(u32, 1) << @intCast(n)) - 1;
                while (mask != 0) : (mask &= mask - 1) {
                    const s = bucket[(n -% 1 -% @ctz(mask)) & (simd_depth - 1)];
                    const c: usize = s & ~tagged_mask;
                    if (c >= p) continue;
                    const d = p - c;
                    if (d > max_dist) break;
                    if (worthComparing(best_len, self.data[c + best_len] == self.data[p + best_len])) {
                        const l = matchLen(self.data, c, p, max_len);
                        if (l >= min_match) {
                            const g = self.gain(l, d);
                            if (g > best_gain) {
                                best_gain = g;
                                best_len = l;
                                best_dist = d;
                                if (l == max_len) break;
                            }
                        }
                    }
                }
                if (best_len == 0) return null;
                return .{ .len = @intCast(best_len), .dist = @intCast(best_dist), .gain = best_gain };
            }
            var k: u32 = 0;
            while (k < valid) : (k += 1) {
                const s = bucket[(n -% 1 -% k) & (self.depth - 1)];
                if (tagged and s & tagged_mask != hv.tag) continue;
                const c: usize = s & ~m;
                if (c >= p) continue;
                const d = p - c;
                // Older slots are further back still.
                if (d > max_dist) break;
                if (worthComparing(best_len, self.data[c + best_len] == self.data[p + best_len])) {
                    const l = matchLen(self.data, c, p, max_len);
                    if (l >= min_match) {
                        const g = self.gain(l, d);
                        if (g > best_gain) {
                            best_gain = g;
                            best_len = l;
                            best_dist = d;
                            if (l == max_len) break;
                        }
                    }
                }
            }
            if (best_len == 0) return null;
            return .{ .len = @intCast(best_len), .dist = @intCast(best_dist), .gain = best_gain };
        }

        /// A static-dictionary word for `p` (RFC 7932 §8) at `.q9`, as
        /// google/brotli's qualities 5–9 look for one when the hash found no copy
        /// (`SearchInStaticDictionary`, `TestStaticDictionaryItem`, MIT, see
        /// `NOTICE`): the two words `dictionary_hash` keeps for the first four
        /// bytes, as a whole or with its last 1–9 bytes cut off (the
        /// OMIT_LAST transforms). `out_max`: how far back the output reaches —
        /// a word's distance lies beyond it and a prefix dictionary's.
        fn findWord(self: *Self, p: usize, out_max: usize, limit: usize) align(64) ?Match {
            if (self.dict_matches < self.dict_lookups >> 7) return null;
            if (p + 4 > limit) return null;
            const max_len = limit - p;
            const key = dictionary_hash.hash14(self.data[p..][0..4]) << 1;
            self.dict_lookups += 2;
            // Both buckets' lengths at once: most are empty.
            const lens = dictionary_hash.table.lengths[key..][0..2].*;
            if (@as(u16, @bitCast(lens)) == 0) return null;
            var best: ?Match = null;
            var best_gain: f32 = 0;
            for (lens, key..) |len8, b| {
                const len: usize = len8;
                if (len == 0 or len > max_len) continue;
                const j: usize = dictionary_hash.table.words[b];
                const word = dictionary.data[dictionary.offsets_by_length[len] + len * j ..][0..len];
                const l = wordMatchLen(word, self.data[p..][0..len]);
                if (l == 0 or l + omit_last_transforms.len <= len) continue;
                const t: usize = omit_last_transforms[len - l];
                const d = out_max + self.dict_len + 1 + j + (t << @intCast(dictionary.size_bits_by_length[len]));
                if (d > max_code_distance) continue;
                const g = self.gain(l, d);
                if (g <= best_gain) continue;
                self.dict_matches += 1;
                best_gain = g;
                best = .{ .len = @intCast(l), .dist = @intCast(d), .gain = g, .word = @intCast(len) };
            }
            return best;
        }

        /// Length of the common prefix of `word` and `at` (as long), eight
        /// bytes per step.
        fn wordMatchLen(word: []const u8, at: []const u8) usize {
            var l: usize = 0;
            while (l + 8 <= word.len) : (l += 8) {
                const x = std.mem.readInt(u64, word[l..][0..8], .little) ^ std.mem.readInt(u64, at[l..][0..8], .little);
                if (x != 0) return l + @ctz(x) / 8;
            }
            while (l < word.len and word[l] == at[l]) l += 1;
            return l;
        }

        /// Cheap reject: whether a candidate gets the byte-by-byte compare —
        /// it can beat `best_len` (the byte there agrees, `next_eq`), or nothing
        /// was found yet. Without the short-circuit `or` it is one branch, and
        /// `.q9` on text 5 % faster (2026-10-15).
        inline fn worthComparing(best_len: usize, next_eq: bool) bool {
            return (@intFromBool(best_len == 0) | @intFromBool(next_eq)) != 0;
        }

        /// Whether lookups in `block` should skip slots by their tag: when the
        /// slots have tags and the block looks binary. On text most of a
        /// bucket shares its first four bytes and the test only cost
        /// mispredicted branches (`.q9` +28 %, 2026-10-15).
        fn tagsPay(self: *const Self, block: []const u8) bool {
            if (wide) return self.tag_mask != 0;
            return self.tag_mask != 0 and looksBinary(block);
        }

        /// Every copy for `p` that is longer than any nearer one (so the
        /// candidates' lengths rise and their distances too), as `find` walks the
        /// bucket: what a shortest-path parse chooses from (`.q11`). Returns how
        /// many of `out` are set.
        fn collect(self: *const Self, comptime px: bool, comptime tagged: bool, p: usize, max_dist: usize, limit: usize, out: *[max_cands]Cand) usize {
            if (p + hash_len > limit) return 0;
            const max_len = @min(limit - p, max_match);
            const hv = self.hash(p);
            const h = hv.bucket;
            const n = self.count[h];
            const valid = if (n < self.depth) n else self.depth;
            const bucket = self.slots[h << self.depth_log ..][0..self.depth];
            const m = if (tagged) tagged_mask else self.tag_mask;
            var found: usize = 0;
            var best_len: usize = 0;
            var k: u32 = 0;
            while (k < valid) : (k += 1) {
                const s = bucket[(n -% 1 -% k) & (self.depth - 1)];
                if (tagged and s & tagged_mask != hv.tag) continue;
                const c: usize = s & ~m;
                if (c >= p) continue;
                const d = p - c;
                if (d > max_dist) break;
                if (worthComparing(best_len, self.data[c + best_len] == self.data[p + best_len])) {
                    const l = matchLen(self.data, c, p, max_len);
                    if (l >= min_match and l > best_len) {
                        out[found] = .{ .len = @intCast(l), .dist = @intCast(d) };
                        found += 1;
                        best_len = l;
                        if (l == max_len or found == max_cands) break;
                    }
                }
            }
            // The dictionary's distances lie past every one above, so its
            // copies, each longer than all before, keep the order.
            if (px and best_len < max_len) return self.dict.?.collect(self.data, p, max_dist, max_len, best_len, out, found);
            return found;
        }
    };
}

const Matcher = MatcherT(false);
const WideMatcher = MatcherT(true);

/// A copy `Matcher.collect` found: length and the decoder's distance.
const Cand = struct { len: u32, dist: u32 };
/// Most candidates kept for a position — the parse's memory: 8 bytes each
/// per position of the block. 16, 32 and 48 gave the same sizes on the bench
/// payloads (2026-10-15).
const max_cands = 16;

// `.q4` has a match finder of its own (2026-10-14). `Matcher` keeps a count
// per bucket to know which slots are written and walks them newest first: a
// load and a store of the count on every insert, and a walk whose length the
// count decides. Here a bucket has a fixed `fast_sweep` slots, all valid from
// the start (the table is zeroed, a zero slot is position 0 — a real if
// unlikely candidate that the compare settles), and a position goes to the
// slot its own bits pick, as google/brotli's quick hashers do — an insert is
// one store. The values below were swept on the bench payloads (json, html,
// alice29) for size and time together:
// - 6 hashed bytes: smaller than 5 on all three (text −2 %), 7 lost on text;
// - 4 slots × 2^16 buckets: 8 slots cost ~15 % time for ~1 %, 2^17 buckets
//   ~10 % time for 0.3 % on text (a 2 MiB table to clear per call);
// - the lazy step is worth 4-7 % of size and is skipped from 32 bytes on (16
//   cost html 2 %); the second-last ring distance, or 3-byte copies at the
//   ring, never won.

/// Bytes `FastMatcher` hashes.
const fast_hash_len = 6;
/// Slots per bucket of `FastMatcher`.
const fast_sweep = 4;
/// log2 of `FastMatcher`'s most buckets.
const fast_bucket_log_max = 16;
/// Literals in a row after which `buildCommandsFast` starts to skip positions.
const fast_skip_after = 64;
/// Longest step through a run of literals.
const fast_skip_max = 16;
/// Matches shorter than this get the lazy step (try the next position).
const fast_lazy_max_len = 32;
/// Copies up to this long have every position inserted; longer ones their
/// first and last `fast_dense_insert / 2` and every fourth between.
const fast_dense_insert = 32;
/// `.q4` and a prefix dictionary (2026-10-16): google's q4 does not search
/// one at all. Here its bucket's newest 8 positions, where the window found
/// no copy: against google's q4 (its dictionary prepared once) 0.83–1.06× the
/// time for 9–18 % smaller responses of 4–32 KiB; every lookup and 4
/// positions cost 1.13–1.19×, 2 positions 0.90–1.13×.
const fast_dict_items = 8;
/// `literalCost` sampling at `.q4`.
const fast_cost_stride = 4;

const FastMatcher = struct {
    lit_cost: f32 = 8,
    history: History = .{},
    /// As `Matcher.dict`.
    dict: ?DictRef = null,
    /// `fast_sweep` slots per bucket.
    table: []u32,
    hash_shift: u6,
    data: []const u8,

    /// The `u32`s of the table for an input of about `size` bytes.
    fn tableLen(size: usize) usize {
        return @as(usize, 1) << @intCast(bucketLog(size, fast_bucket_log_max) + std.math.log2_int(u32, fast_sweep));
    }

    /// The table for an input of about `size` bytes, in `mem` (at least
    /// `tableLen`, contents anything); `data` is set by the caller.
    fn initIn(mem: []u32, size: usize) FastMatcher {
        const bucket_log = bucketLog(size, fast_bucket_log_max);
        const table = mem[0..tableLen(size)];
        Matcher.fillZero(table);
        return .{ .table = table, .hash_shift = @intCast(64 - @as(u7, bucket_log)), .data = &.{} };
    }

    /// Empty, as `init` leaves it.
    fn reset(self: *FastMatcher) void {
        Matcher.fillZero(self.table);
    }

    /// As `Matcher.shift`.
    fn shift(self: *FastMatcher, by: u32) void {
        for (self.table) |*s| s.* = History.shiftPos(s.*, by);
        self.history.dropped += by;
    }

    /// Bucket of the five bytes at `p`; needs eight readable bytes.
    fn bucket(self: *const FastMatcher, p: usize) usize {
        const v = std.mem.readInt(u64, self.data[p..][0..8], .little) << (64 - 8 * fast_hash_len);
        return @intCast((v *% 0x1e35a7bd1e35a7bd) >> self.hash_shift);
    }

    fn insert(self: *FastMatcher, p: usize) void {
        if (p + 8 > self.data.len) return;
        self.table[self.bucket(p) * fast_sweep + ((p >> 3) & (fast_sweep - 1))] = @intCast(p);
    }

    fn prefetch(self: *const FastMatcher, p: usize) void {
        if (p + 8 > self.data.len) return;
        @prefetch(&self.table[self.bucket(p) * fast_sweep], .{});
    }

    /// As `Matcher.find`, over the bucket's slots and the last distance (the
    /// second-last, or copies of three bytes at either, never won here).
    fn find(self: *const FastMatcher, comptime px: bool, p: usize, ring: *const DistRing, max_dist: usize, limit: usize) ?Match {
        if (p + 8 > limit) return null;
        const max_len = @min(limit - p, max_match);
        var best_len: usize = 0;
        var best_dist: usize = 0;
        var best_gain: f32 = 0;
        const last: usize = ring.last[0];
        if (last <= max_dist and std.mem.readInt(u32, self.data[p - last ..][0..4], .little) == std.mem.readInt(u32, self.data[p..][0..4], .little)) {
            best_len = Matcher.matchLen(self.data, p - last, p, max_len);
            best_dist = last;
            best_gain = @as(f32, @floatFromInt(best_len)) * self.lit_cost - 3;
        }
        if (best_len == max_len) return .{ .len = @intCast(best_len), .dist = @intCast(best_dist), .gain = best_gain };
        const slots = self.table[self.bucket(p) * fast_sweep ..][0..fast_sweep];
        for (slots) |s| {
            const c: usize = s;
            if (c >= p) continue;
            const d = p - c;
            if (d > max_dist) continue;
            if (d == best_dist) continue;
            if (self.data[c + best_len] != self.data[p + best_len]) continue;
            const l = Matcher.matchLen(self.data, c, p, max_len);
            if (l < min_match) continue;
            const dist_bits: f32 = @floatFromInt(std.math.log2_int(usize, d));
            const g = @as(f32, @floatFromInt(l)) * self.lit_cost - dist_bits - 6;
            if (g > best_gain) {
                best_gain = g;
                best_len = l;
                best_dist = d;
                if (l == max_len) break;
            }
        }
        // The dictionary only where the window found nothing (`fast_dict_items`).
        if (px and best_len == 0) {
            var best: Best = .{ .len = best_len, .dist = best_dist, .gain = best_gain };
            self.dict.?.search(fast_dict_items, self.data, p, max_dist, max_len, self.lit_cost, ring.last[0..1], &best);
            best_len = best.len;
            best_dist = best.dist;
            best_gain = best.gain;
        }
        if (best_len == 0) return null;
        return .{ .len = @intCast(best_len), .dist = @intCast(best_dist), .gain = best_gain };
    }
};

// `.q1` (2026-10-15, R13; `.q0` with it until 2026-10-16, now `writeQ0`):
// a match finder of one slot per bucket,
// written over at every lookup, and a parse that takes the first match it
// finds — no gain, no lazy step — and steps faster through data that has
// stopped matching (one more byte of step per `2^skip_log2` misses, as
// LZ4/Snappy do). The parse writes each command already resolved — symbol,
// extra bits, distance code — with the block's command and distance
// histograms, and copies the literals into one buffer (`FragBlock`); the
// block is then written with one code per category and no literal contexts
// (`writeFragmentBlock`). Going through `Cmd`s and a resolving pass, as the
// other levels do, cost about 80 cycles per command, which is all a
// command may cost here (google q0: about 70 cycles a command, parse and
// write together; bench payloads, 2026-10-15). `FragLevel` names what the
// parse looks at.

/// Bytes `FragMatcher` hashes.
const frag_hash_len = 5;
/// log2 of `FragMatcher`'s most buckets.
const frag_bucket_log_max = 15;

/// The parse's choices (`.q1`'s; `.q0`'s own were a step growing every 8
/// misses, the last distance only after a copy, nothing inserted from a
/// copy, no backward extension — 1.2–1.55× google's q0 time, 2026-10-15).
const FragLevel = struct {
    /// Misses per extra byte of step (log2).
    skip_log2: u5,
    /// Every position is checked against the last distance first, not only
    /// the one after a copy.
    ring_every: bool,
    /// Positions inside a copy inserted (from its end backwards).
    tail_inserts: u8,
    /// A match is extended backwards over the literals before it.
    extend_back: bool,
};

fn fragLevel(e: Effort) FragLevel {
    std.debug.assert(e == .q1);
    return .{ .skip_log2 = 5, .ring_every = true, .tail_inserts = 2, .extend_back = true };
}

const FragMatcher = struct {
    history: History = .{},
    /// As `Matcher.dict`.
    dict: ?DictRef = null,
    /// One slot per bucket: the last position hashed there.
    table: []u32,
    hash_shift: u6,
    data: []const u8,

    /// As `FastMatcher.tableLen`.
    fn tableLen(size: usize) usize {
        return @as(usize, 1) << @intCast(bucketLog(size, frag_bucket_log_max));
    }

    /// As `FastMatcher.initIn`.
    fn initIn(mem: []u32, size: usize) FragMatcher {
        const bucket_log = bucketLog(size, frag_bucket_log_max);
        const table = mem[0..tableLen(size)];
        Matcher.fillZero(table);
        return .{ .table = table, .hash_shift = @intCast(64 - @as(u7, bucket_log)), .data = &.{} };
    }

    fn reset(self: *FragMatcher) void {
        Matcher.fillZero(self.table);
    }

    fn shift(self: *FragMatcher, by: u32) void {
        for (self.table) |*s| s.* = History.shiftPos(s.*, by);
        self.history.dropped += by;
    }

    /// Bucket of the `frag_hash_len` bytes at `p`; needs eight readable bytes.
    inline fn bucket(self: *const FragMatcher, p: usize) usize {
        const v = std.mem.readInt(u64, self.data[p..][0..8], .little) << (64 - 8 * frag_hash_len);
        return @intCast((v *% 0x1e35a7bd1e35a7bd) >> self.hash_shift);
    }

    fn insert(self: *FragMatcher, p: usize) void {
        if (p + 8 > self.data.len) return;
        self.table[self.bucket(p)] = @intCast(p);
    }
};

/// A command of a `.q0`/`.q1` block, resolved: what it writes but its
/// literals (those are `FragBlock.lits`, in order), in two words. `cmd`:
/// the command symbol (10 bits), its extra bit count (6), then the insert's
/// extra bits and the copy's — the stream has them right after the symbol,
/// so the writer puts all three at once. `dst`: the distance symbol plus one
/// (8 bits, 0: none — the last distance by an implicit-distance command, or
/// the block's final literals), its extra bit count (5), the insert length
/// (21), the extra bits (30).
const FragRec = struct {
    cmd: u64,
    dst: u64,

    fn sym(r: FragRec) usize {
        return @intCast(r.cmd & 1023);
    }
    fn extraN(r: FragRec) u64 {
        return (r.cmd >> 10) & 63;
    }
    fn distSym1(r: FragRec) usize {
        return @intCast(r.dst & 255);
    }
    fn distN(r: FragRec) u64 {
        return (r.dst >> 8) & 31;
    }
    fn insertLen(r: FragRec) usize {
        return @intCast((r.dst >> 13) & 0x1f_ffff);
    }
};

/// `sym[at_last][insert code * 24 + copy code]`: the command symbol of a
/// copy, with bit 15 set when a distance symbol follows. At the last
/// distance the implicit-distance form where there is one.
const frag_sym: [2][24 * 24]u16 = blk: {
    var t: [2][24 * 24]u16 = undefined;
    for (0..24) |ic| for (0..24) |cc| {
        const explicit = cmd_tables.sym[ic][cc] | 0x8000;
        t[0][ic * 24 + cc] = explicit;
        const imp = cmd_tables.implicit[ic][cc];
        t[1][ic * 24 + cc] = if (imp != 0xffff) imp else explicit;
    };
    break :blk t;
};

/// A `.q0`/`.q1` block between its parse and its writer.
const FragBlock = struct {
    recs: std.ArrayListUnmanaged(FragRec) = .empty,
    /// The literals, then `lit_pad` zeros (the writer reads groups of three).
    lits: std.ArrayListUnmanaged(u8) = .empty,
    cmd_counts: [tables.num_command_symbols]u32 = undefined,
    /// Distance symbols plus one: `[0]` counts the commands without one.
    dist_counts1: [dist_alphabet_large + 1]u32 = undefined,
    /// The decoder's ring after the block.
    ring: DistRing = .{},
    /// Bytes the commands produce (the block's length).
    covered: usize = 0,

    const lit_pad = 16;

    fn deinit(b: *FragBlock, gpa: std.mem.Allocator) void {
        b.recs.deinit(gpa);
        b.lits.deinit(gpa);
    }
};

/// The command for `insert` literals and a copy of `copy_len` bytes at
/// `dist` (`copy_len` 0: the block's final literals), resolved against the
/// decoder's last distance `last`. Every distance the parse makes has a
/// code: within the window, or a prefix dictionary's up to
/// `max_code_distance` (`History.reach`); a large window's alphabet reaches
/// past any window this encoder makes.
inline fn fragResolve(insert: usize, copy_len: usize, dist: usize, last: usize) FragRec {
    const ie: u64 = if (insert < length_lut_len) frag_ins_lut[insert] else packLen(insert, lengthCodeScan(&cmd_tables.insert_off, &cmd_tables.insert_nbits, @intCast(insert)).?);
    const cl = if (copy_len == 0) cmd_tables.copy_off[0] else copy_len;
    const ce: u64 = if (cl < length_lut_len) frag_copy_lut[cl] else packLen(cl, lengthCodeScan(&cmd_tables.copy_off, &cmd_tables.copy_nbits, @intCast(cl)).?);
    const inb = (ie >> 5) & 31;
    const extra = (insert - (ie >> 10)) | (cl - (ce >> 10)) << @intCast(inb);
    const extra_n = inb + ((ce >> 5) & 31);
    const idx: usize = @intCast((ie & 31) * 24 + (ce & 31));
    const at_last = copy_len == 0 or dist == last;
    const e: u64 = frag_sym[@intFromBool(at_last)][idx];
    var dst: u64 = @as(u64, insert) << 13;
    if (e >> 15 != 0 and copy_len != 0) {
        if (dist == last) {
            dst |= 1; // short code 0, no extra bits
        } else {
            // `distanceCode` for NPOSTFIX = NDIRECT = 0.
            const x: u64 = @as(u64, dist) + 3;
            const nb: u64 = 63 - @clz(x) - 1;
            const half = (x >> @intCast(nb)) & 1;
            const dsym = tables.num_distance_short_codes + 2 * (nb - 1) + half;
            const dext = x - ((2 + half) << @intCast(nb));
            dst |= (dsym + 1) | nb << 8 | dext << 34;
        }
    }
    return .{ .cmd = (e & 1023) | extra_n << 10 | extra << 16, .dst = dst };
}

/// `lengthCode`'s result for `len` as a `frag_*_lut` entry: code (5 bits),
/// extra bit count (5), offset.
fn packLen(len: usize, c: LenCode) u64 {
    return @as(u64, c.code) | @as(u64, c.nbits) << 5 | @as(u64, len - c.extra) << 10;
}

const frag_ins_lut = packedLengthLut(&cmd_tables.insert_off, &cmd_tables.insert_nbits);
const frag_copy_lut = packedLengthLut(&cmd_tables.copy_off, &cmd_tables.copy_nbits);

/// What `fragCommand` needs between the parse's commands: in memory, so the
/// parse loop has the registers to itself.
const FragState = struct {
    data: []const u8,
    /// The next record and literal (`FragBlock.recs`/`lits`' room).
    rec: [*]FragRec,
    lit: [*]u8,
    cmd_counts: *[tables.num_command_symbols]u32,
    /// `FragBlock.dist_counts`, from "none" on (`FragRec.distSym1`).
    dist_counts1: *[dist_alphabet_large + 1]u32,
    ring: DistRing,
    /// Bytes the commands so far produce.
    covered: usize = 0,
};

/// The command for the literals `data[lit_start..p)` and a copy of `len`
/// bytes at `dist` (`len` 0: the block's final literals) into `st`. (Not
/// inlined it saved instructions but cost 4-5 % cycles, 2026-10-15.)
inline fn fragCommand(st: *FragState, lit_start: usize, p: usize, len: usize, dist: usize) void {
    const insert = p - lit_start;
    const r = fragResolve(insert, len, dist, st.ring.last[0]);
    st.rec[0] = r;
    st.rec += 1;
    st.cmd_counts[r.sym()] += 1;
    // (Index 0 of `dist_counts1` is "none", never written out.)
    st.dist_counts1[r.distSym1()] += 1;
    // The literals, 16 bytes at a time while the input has them: one round
    // for nearly every command, not a loop of unknown length.
    const data = st.data;
    if (lit_start + insert + 16 <= data.len) {
        var k: usize = 0;
        while (k < insert) : (k += 16) st.lit[k..][0..16].* = data[lit_start + k ..][0..16].*;
    } else @memcpy(st.lit[0..insert], data[lit_start..][0..insert]);
    st.lit += insert;
    st.covered += insert + len;
    if (len != 0 and dist != st.ring.last[0]) st.ring.update(@intCast(dist), null);
}

/// `.q1`'s parse of `data[start..end)` into `fb`; the matches as
/// `buildCommands`'s: they may reach back before `start`, never past `end`.
/// The loop only looks for the next match; `fragCommand` writes it. `px`:
/// where the table has no copy, the newest position of the prefix
/// dictionary's bucket is tried (google/brotli's quality 1 does not search a
/// dictionary at all). Responses of 4–32 KiB against dictionaries of 16 and
/// 256 KiB: 6–14 % smaller than without, in 0.98–1.17× the time
/// (2026-10-16).
fn buildFrag(
    comptime px: bool,
    comptime lv: FragLevel,
    gpa: std.mem.Allocator,
    matcher: *FragMatcher,
    start: usize,
    end: usize,
    max_dist: usize,
    ring_in: DistRing,
    fb: *FragBlock,
) std.mem.Allocator.Error!void {
    // Everything the loop reads is a local: a store into the table may alias
    // any field behind a pointer, which was then loaded again after it.
    const data = matcher.data;
    const table = matcher.table;
    const hshift = matcher.hash_shift;
    const dref: DictRef = if (px) matcher.dict.? else undefined;
    const x = matcher.history;
    const n = end - start;
    // Every command but the last copies at least `min_match` bytes; the
    // literal copy may write 15 bytes past the last literal.
    fb.recs.clearRetainingCapacity();
    fb.lits.clearRetainingCapacity();
    try fb.recs.ensureTotalCapacity(gpa, n / min_match + 2);
    try fb.lits.ensureTotalCapacity(gpa, n + 16 + FragBlock.lit_pad);
    Matcher.fillZero(&fb.cmd_counts);
    Matcher.fillZero(&fb.dist_counts1);
    var st: FragState = .{
        .data = data,
        .rec = fb.recs.items.ptr,
        .lit = fb.lits.items.ptr,
        .cmd_counts = &fb.cmd_counts,
        .dist_counts1 = &fb.dist_counts1,
        .ring = ring_in,
    };
    // `History.outMax` as one add: how far back the output reaches from `p`
    // is `min(max_dist, p + out_off)`.
    const out_off = x.dropped;

    var p = start;
    var lit_start = start;
    // Hashing reads eight bytes; the last ones of the block stay literals.
    const limit = if (end >= 8 and end - 8 >= start) end - 8 + 1 else start;
    while (true) {
        var dist: usize = 0;
        var len: usize = 0;
        var misses: usize = 0;
        const last: usize = st.ring.last[0];
        // The last distance at the first position: no distance bits.
        if (!lv.ring_every and p < limit and last <= @min(max_dist, p +% out_off) and
            std.mem.readInt(u32, data[p - last ..][0..4], .little) == std.mem.readInt(u32, data[p..][0..4], .little))
        {
            dist = last;
            len = Matcher.matchLen(data, p - last, p, @min(end - p, max_match));
        }
        if (len == 0) while (p < limit) {
            const out_max = @min(max_dist, p +% out_off);
            const cur4 = std.mem.readInt(u32, data[p..][0..4], .little);
            if (lv.ring_every and last <= out_max and
                std.mem.readInt(u32, data[p - last ..][0..4], .little) == cur4)
            {
                dist = last;
                len = Matcher.matchLen(data, p - last, p, @min(end - p, max_match));
                break;
            }
            const v = std.mem.readInt(u64, data[p..][0..8], .little) << (64 - 8 * frag_hash_len);
            const h: usize = @intCast((v *% 0x1e35a7bd1e35a7bd) >> hshift);
            const c: usize = table[h];
            table[h] = @intCast(p);
            if (c < p and std.mem.readInt(u32, data[c..][0..4], .little) == cur4) {
                if (p - c <= out_max) {
                    dist = p - c;
                    len = Matcher.matchLen(data, c, p, @min(end - p, max_match));
                    if (lv.extend_back) {
                        var cc = c;
                        while (p > lit_start and cc > 0 and data[cc - 1] == data[p - 1] and len < max_match) {
                            p -= 1;
                            cc -= 1;
                            len += 1;
                        }
                    }
                    break;
                }
            }
            if (px) {
                const src = dref.pd.source;
                var ch = dref.pd.chain(data[p..][0..PreparedDictionary.read_len]);
                if (ch.next()) |o32| {
                    // An indexed position has `read_len` bytes after it.
                    const o: usize = o32;
                    const d = out_max + src.len - o;
                    if (d <= max_code_distance and std.mem.readInt(u32, src[o..][0..4], .little) == cur4) {
                        dist = d;
                        len = matchLenAt(src[o..].ptr, data[p..].ptr, @min(end - p, max_match, src.len - o));
                        break;
                    }
                }
            }
            misses += 1;
            p += 1 + (misses >> lv.skip_log2);
        };
        if (len == 0) {
            // The block's final literals, if any.
            if (lit_start < end) fragCommand(&st, lit_start, end, 0, 0);
            break;
        }
        fragCommand(&st, lit_start, p, len, dist);
        p += len;
        lit_start = p;
        var k: usize = 1;
        while (k <= lv.tail_inserts and k < len) : (k += 1) {
            const q = p - k;
            if (q < limit) {
                const v = std.mem.readInt(u64, data[q..][0..8], .little) << (64 - 8 * frag_hash_len);
                table[@intCast((v *% 0x1e35a7bd1e35a7bd) >> hshift)] = @intCast(q);
            }
        }
    }
    fb.recs.items.len = st.rec - fb.recs.items.ptr;
    fb.lits.items.len = st.lit - fb.lits.items.ptr;
    @memset(st.lit[0..FragBlock.lit_pad], 0);
    fb.ring = st.ring;
    fb.covered = st.covered;
}

// ---------------------------------------------------------------------------
// Commands.

/// A resolved insert-and-copy command. `copy_len == 0` marks the block's final,
/// literals-only command: the decoder still *reads* the copy extra bits before
/// noticing MLEN is exhausted, so they are written, but no copy is performed.
const Cmd = struct {
    insert_len: u32,
    /// The length the command's symbol names: the copy's, or — for a
    /// dictionary word (`out_len != 0`) — the word's.
    copy_len: u32,
    dist: u32,
    /// Zero for a copy. For a static-dictionary word (RFC 7932 §8, `.q11`):
    /// the bytes its transformed form produces; `dist` then names the word
    /// (`dictDistance`), beyond everything a copy can reach.
    out_len: u32 = 0,

    /// Bytes of output the command's copy part produces.
    fn produced(c: Cmd) u32 {
        return if (c.out_len != 0) c.out_len else c.copy_len;
    }
};

/// Greedy + one-step-lazy parse of `input[start..end)`. Matches may reach back
/// before `start` (the decoder's history is the whole output) but never past
/// `end`, so the commands consume exactly `end - start` bytes.
fn buildCommands(
    comptime ring_n: u3,
    /// Literals in a row after which positions are skipped.
    comptime skip_after: usize,
    comptime px: bool,
    /// Lookups skip slots by tag (`Matcher.tagsPay`).
    comptime tagged: bool,
    /// Tags compared a bucket at once (`Matcher.find`).
    comptime simd: bool,
    /// Static-dictionary words where no copy is found (`Matcher.findWord`).
    comptime words: bool,
    gpa: std.mem.Allocator,
    /// `*Matcher` or `*WideMatcher`.
    matcher: anytype,
    start: usize,
    end: usize,
    max_dist: usize,
    out: *std.ArrayListUnmanaged(Cmd),
) align(64) std.mem.Allocator.Error!void {
    const sparse = skip_after != std.math.maxInt(usize);
    var p = start;
    var lit_start = start;
    var pending: ?Match = null;
    // From here on, positions are skipped (google/brotli's
    // `apply_random_heuristics`, `backward_references_inc.h`, MIT, see
    // `NOTICE`): `skip_after` past the last copy's start plus twice its length.
    var skip_from = start +| skip_after;
    // A local copy: read through `matcher` it would be loaded again at
    // every position.
    const x = matcher.history;
    matcher.lit_cost = literalCost(matcher.data[start..end], 1);

    while (p < end) {
        matcher.prefetch(p + 1);
        const m = pending orelse matcher.find(ring_n, px, tagged, simd, p, x.outMax(p, max_dist), end) orelse
            if (words) matcher.findWord(p, x.outMax(p, max_dist), end) else null;
        pending = null;
        if (m == null) {
            matcher.insert(p);
            p += 1;
            // A long run without a match (binary or compressed data): the
            // next 8 positions are only inserted, every second one, and
            // `4 * skip_after` later the next 16, every fourth — google's
            // steps (the gradual `.q4`-like ramp before cost fonts 1.3× of
            // google q6's time, 2026-10-16).
            if (sparse and p > skip_from) {
                const far = p > skip_from + 4 * skip_after;
                const step: usize = if (far) 4 else 2;
                const jump = @min(p + step * 4, end);
                while (p < jump) : (p += step) matcher.insert(p);
            }
            continue;
        }
        matcher.insert(p);
        if (p + 1 < end) {
            const next = matcher.find(ring_n, px, tagged, simd, p + 1, x.outMax(p + 1, max_dist), end) orelse
                if (words) matcher.findWord(p + 1, x.outMax(p + 1, max_dist), end) else null;
            if (next) |b| {
                // One literal more is spent to take `b`, so it must save
                // more than that literal costs on top of what `m` saves.
                if (b.gain > m.?.gain + matcher.lit_cost) {
                    pending = b;
                    p += 1; // spend one more literal, take the better match
                    continue;
                }
            }
        }
        const len = m.?.len;
        const word = m.?.word;
        try out.append(gpa, .{
            .insert_len = @intCast(p - lit_start),
            .copy_len = if (word != 0) word else len,
            .dist = m.?.dist,
            .out_len = if (word != 0) len else 0,
        });
        // `DistRing.update` pushes every distance but the last one (code 0);
        // a word's distance is not pushed.
        if (ring_n != 0 and word == 0 and m.?.dist != matcher.ring.last[0]) matcher.ring.update(m.?.dist, null);
        matcher.prefetch(p + len);
        var q = p + 1;
        if (sparse) {
            skip_from = p + 2 * @as(usize, len) + skip_after;
            // A run (a copy from less than a quarter of its length back):
            // only its last `4 * dist` positions, so that it does not fill
            // its bucket with copies of itself (google's StoreRange bounds).
            const d: usize = m.?.dist;
            if (word == 0 and d < len >> 2) q = @max(q, p + len - 4 * d);
        }
        while (q < p + len) : (q += 1) matcher.insert(q);
        p += len;
        lit_start = p;
    }

    if (lit_start < end) {
        try out.append(gpa, .{ .insert_len = @intCast(end - lit_start), .copy_len = 0, .dist = 0 });
    }
}

/// Whether `block` has the control bytes text never has (beyond tab, line
/// feed, form feed and carriage return) in more than one byte of 128:
/// fonts, executables and archives are full of zeros and small numbers.
/// Every 16th byte is looked at: a scan of all of them was 6 % of
/// `.q6` on text (bench, 2026-10-15).
fn looksBinary(block: []const u8) bool {
    var n: usize = 0;
    var i: usize = 0;
    while (i < block.len) : (i += 16) {
        const b = block[i];
        n += @intFromBool(b < 0x20 and b != '\t' and b != '\n' and b != '\r' and b != 0x0c);
    }
    return n * 128 * 16 > block.len;
}

/// The block's order-0 entropy in bits per byte (at least 1): the price of a
/// literal, so what a match saves per byte it covers.
/// Every `stride`-th byte is counted.
fn literalCost(block: []const u8, comptime stride: usize) f32 {
    var hist = [_]u32{0} ** 256;
    var i: usize = 0;
    while (i < block.len) : (i += stride) hist[block[i]] += 1;
    var sum: f64 = 0;
    for (hist) |c| sum += nlog2n(c);
    const counted = (block.len + stride - 1) / stride;
    const n: f64 = @floatFromInt(counted);
    return @floatCast(@max(1.0, (nlog2n(counted) - sum) / n));
}

/// `.q4`'s parse of `input[start..end)`, same contract as `buildCommands`:
/// greedy with a lazy step for short matches only, and through a run of
/// literals it looks at fewer positions the longer the run (from
/// `fast_skip_after` literals on, every second, then every third... up to
/// `fast_skip_max`): data that found no match for a while is unlikely to find
/// one at the next byte, and incompressible input passes at a fraction of the
/// lookups.
fn buildCommandsFast(
    comptime px: bool,
    gpa: std.mem.Allocator,
    matcher: *FastMatcher,
    start: usize,
    end: usize,
    max_dist: usize,
    ring_in: DistRing,
    out: *std.ArrayListUnmanaged(Cmd),
) std.mem.Allocator.Error!void {
    var p = start;
    var lit_start = start;
    var ring = ring_in;
    const x = matcher.history; // as in `buildCommands`
    // A price, not a code: a quarter of the bytes estimate it well enough.
    matcher.lit_cost = literalCost(matcher.data[start..end], fast_cost_stride);

    while (p < end) {
        matcher.prefetch(p + 1);
        var m = matcher.find(px, p, &ring, x.outMax(p, max_dist), end) orelse {
            matcher.insert(p);
            const run = p - lit_start;
            p += if (run < fast_skip_after) 1 else @min(fast_skip_max, 1 + ((run - fast_skip_after) >> 5));
            continue;
        };
        if (m.len < fast_lazy_max_len) {
            matcher.insert(p);
            while (p + 1 < end) {
                const b = matcher.find(px, p + 1, &ring, x.outMax(p + 1, max_dist), end) orelse break;
                // One literal more is spent to take `b`.
                if (b.gain <= m.gain + matcher.lit_cost) break;
                p += 1;
                matcher.insert(p);
                m = b;
            }
        }
        try out.append(gpa, .{
            .insert_len = @intCast(p - lit_start),
            .copy_len = m.len,
            .dist = m.dist,
        });
        if (m.dist != ring.last[0]) ring.update(m.dist, null);
        matcher.prefetch(p + m.len);
        var q = p;
        if (m.len <= fast_dense_insert) {
            while (q < p + m.len) : (q += 1) matcher.insert(q);
        } else {
            // A long copy: its first and last positions in full, every
            // fourth between.
            while (q < p + fast_dense_insert / 2) : (q += 1) matcher.insert(q);
            while (q < p + m.len - fast_dense_insert / 2) : (q += 4) matcher.insert(q);
            q = p + m.len - fast_dense_insert / 2;
            while (q < p + m.len) : (q += 1) matcher.insert(q);
        }
        p += m.len;
        lit_start = p;
    }
    // A skip may have stepped past `end`.
    if (lit_start < end) {
        try out.append(gpa, .{ .insert_len = @intCast(end - lit_start), .copy_len = 0, .dist = 0 });
    }
}

// ---------------------------------------------------------------------------
// Literal context modelling (RFC 7932 §7.1, §7.3).
//
// The decoder picks the literal prefix code by a context id computed from the
// two previous output bytes (`tables.context_lookup`, one of four modes) and a
// context map from the 64 ids to NTREES codes. The encoder histograms the
// block's literals per context, clusters the 64 histograms greedily — merge the
// pair whose union costs the fewest extra bits, while that is cheaper than
// keeping them apart — and tries every mode, keeping the cheapest. The cost is
// an estimate (Shannon bits plus a flat per-code header guess); the store-mode
// comparison afterwards is on real bits.

const num_contexts = 1 << tables.literal_context_bits;
/// NTREES cap for the literal map: more codes cost more headers than they save
/// on the block sizes this encoder emits.
const max_literal_trees = 16;
/// Percentage of ASCII literals above which only the UTF8 context mode is
/// tried (`chooseLiteralModel`).
const ascii_pct = 95;

// ---------------------------------------------------------------------------
// `.q11`: a shortest-path parse. Every position keeps the cheapest way to have
// reached it (a literal from the one before, or the end of a copy), priced
// from histograms of an earlier parse of the same block — the literal prices
// by the block's own context model — and the path from the end back is the
// commands. Positions are priced forward, so each node also carries the last
// four distances of its path: a copy at one of them is named by a short code.
// The price of a command's insert length is paid when the copy is taken (the
// node knows how many literals precede it), not per literal.

/// A copy at least this long is taken whole: its shorter forms and the
/// positions inside it are not looked at (a long run would otherwise cost
/// its length squared).
const max_take_len = 325;
/// Parses of a block: a greedy one from the candidates, then each priced
/// from the commands of the one before; the shortest written wins.
const max_parses = 3;
/// What a symbol the previous parse never used costs, above its share of the
/// block: it would be new to the code.
const unseen_extra_bits = 2.0;

// Static-dictionary words (RFC 7932 §8): a word of 4..24 bytes with one of
// the 121 transforms — a prefix and a suffix around the word or a cut or
// upper-cased form of it — is named by a distance past everything a copy
// reaches: `max_distance + 1 + (transform << size_bits[len]) + word index`,
// with the word's length as the copy length. On text a good share of the
// words are there (q11 on alice29: 1 837 of them, ~13 KB of 152 KB). The
// search finds, at a position, the words whose transformed form is the bytes
// there; the transforms that cut the front of a word (OMIT_FIRST_n) are not
// searched — they would need a suffix index.

/// Bits of the hash of a word's first four bytes (case folded).
const dict_hash_bits = 14;
/// Shortest transformed word worth a candidate: a dictionary reference costs
/// ~30 bits, five literals of text ~22.
const min_dict_out = 5;
const max_dict_cands = 24;

const DictCand = struct { n: u8, wl: u8, t: u8, idx: u16 };

/// A transform the search handles: its cut from the end (OMIT_LAST_n), its
/// case form and its suffix (an offset into `transforms.prefix_suffix`).
const DictForm = struct { t: u8, omit: u8, upper: Upper, suf_off: u8, suf_len: u8 };
const Upper = enum(u2) { none, first, all };

/// The searched transforms (identity, OMIT_LAST_n, UPPERCASE_FIRST / ALL) of
/// each prefix id, and the prefix ids by their prefix's first byte: a
/// position is tried only against the prefixes it can start with.
const dict_tables: struct {
    forms: [50][transforms.num_transforms]DictForm,
    nforms: [50]u8,
    pre_off: [50]u8,
    pre_len: [50]u8,
    by_first: [256][24]u8,
    nby_first: [256]u8,
    empties: [4]u8,
    nempty: u8,
    /// `forms[pid]` is sorted by case form, then cut: those of form `u`
    /// cutting `o` bytes are `forms[pid][at[pid][u][o]..at[pid][u][o + 1]]`.
    at: [50][3][11]u8,
} = blk: {
    @setEvalBranchQuota(100_000);
    var forms: [50][transforms.num_transforms]DictForm = undefined;
    var nforms: [50]u8 = @splat(0);
    var pre_off: [50]u8 = undefined;
    var pre_len: [50]u8 = undefined;
    for (0..50) |id| {
        const off = transforms.prefix_suffix_map[id];
        pre_off[id] = off + 1;
        pre_len[id] = transforms.prefix_suffix[off];
    }
    for (0..transforms.num_transforms) |t| {
        const pid = transforms.transforms_data[t * 3];
        const ty = transforms.transforms_data[t * 3 + 1];
        const sid = transforms.transforms_data[t * 3 + 2];
        if (ty > 11) continue;
        forms[pid][nforms[pid]] = .{
            .t = t,
            .omit = if (ty <= 9) ty else 0,
            .upper = if (ty == 10) .first else if (ty == 11) .all else .none,
            .suf_off = pre_off[sid],
            .suf_len = pre_len[sid],
        };
        nforms[pid] += 1;
    }
    var at: [50][3][11]u8 = undefined;
    for (0..50) |id| {
        // Counting sort by (form, cut).
        var sorted: [transforms.num_transforms]DictForm = undefined;
        var k: u8 = 0;
        for (0..3) |u| {
            for (0..10) |o| {
                at[id][u][o] = k;
                for (forms[id][0..nforms[id]]) |f| {
                    if (@intFromEnum(f.upper) == u and f.omit == o) {
                        sorted[k] = f;
                        k += 1;
                    }
                }
            }
            at[id][u][10] = k;
        }
        forms[id] = sorted;
    }
    var by_first: [256][24]u8 = undefined;
    var nby_first: [256]u8 = @splat(0);
    var empties: [4]u8 = undefined;
    var nempty: u8 = 0;
    for (0..50) |id| {
        if (nforms[id] == 0) continue;
        if (pre_len[id] == 0) {
            empties[nempty] = id;
            nempty += 1;
        } else {
            const b = transforms.prefix_suffix[pre_off[id]];
            by_first[b][nby_first[b]] = id;
            nby_first[b] += 1;
        }
    }
    break :blk .{ .forms = forms, .nforms = nforms, .pre_off = pre_off, .pre_len = pre_len, .by_first = by_first, .nby_first = nby_first, .empties = empties, .nempty = nempty, .at = at };
};

fn psSlice(off: u8, len: u8) []const u8 {
    return transforms.prefix_suffix[off..][0..len];
}

const DictSearch = struct {
    heads: []u32,
    next: []u32,
    wlen: []u8,
    widx: []u16,
    /// Each word's first four bytes folded to lower case (`fold4`): most
    /// of a bucket is told apart by it alone.
    wkey: []u32,

    const n_words = blk: {
        var n: usize = 0;
        for (dictionary.size_bits_by_length) |b| {
            if (b != 0) n += @as(usize, 1) << b;
        }
        break :blk n;
    };

    fn fold4(b: []const u8) u32 {
        var v: u32 = 0;
        for (0..4) |k| {
            var c = b[k];
            if (c >= 'A' and c <= 'Z') c += 32;
            v |= @as(u32, c) << @intCast(8 * k);
        }
        return v;
    }

    fn bucket(key: u32) u32 {
        return (key *% 0x9e3779b1) >> (32 - dict_hash_bits);
    }

    fn init(gpa: std.mem.Allocator) std.mem.Allocator.Error!DictSearch {
        const heads = try gpa.alloc(u32, 1 << dict_hash_bits);
        errdefer gpa.free(heads);
        const next = try gpa.alloc(u32, n_words);
        errdefer gpa.free(next);
        const wlen = try gpa.alloc(u8, n_words);
        errdefer gpa.free(wlen);
        const widx = try gpa.alloc(u16, n_words);
        errdefer gpa.free(widx);
        const wkey = try gpa.alloc(u32, n_words);
        @memset(heads, 0);
        var wid: usize = 0;
        for (dictionary.min_word_length..dictionary.max_word_length + 1) |n| {
            const bits = dictionary.size_bits_by_length[n];
            if (bits == 0) continue;
            for (0..@as(usize, 1) << @intCast(bits)) |idx| {
                const word = dictionary.data[dictionary.offsets_by_length[n] + idx * n ..][0..n];
                wkey[wid] = fold4(word);
                const k = bucket(wkey[wid]);
                wlen[wid] = @intCast(n);
                widx[wid] = @intCast(idx);
                next[wid] = heads[k];
                heads[k] = @intCast(wid + 1);
                wid += 1;
            }
        }
        return .{ .heads = heads, .next = next, .wlen = wlen, .widx = widx, .wkey = wkey };
    }

    fn deinit(self: *DictSearch, gpa: std.mem.Allocator) void {
        gpa.free(self.heads);
        gpa.free(self.next);
        gpa.free(self.wlen);
        gpa.free(self.widx);
        gpa.free(self.wkey);
    }

    /// The (word, transform) pairs whose output is `data[p..]`'s start, the
    /// output ending at `limit` at most.
    fn find(self: *const DictSearch, data: []const u8, p: usize, limit: usize, out: *[max_dict_cands]DictCand) usize {
        var found: usize = 0;
        for (dict_tables.empties[0..dict_tables.nempty]) |pid| {
            found = self.findAfter(data, p, p, limit, pid, out, found);
        }
        if (p >= limit) return found;
        for (dict_tables.by_first[data[p]][0..dict_tables.nby_first[data[p]]]) |pid| {
            const pre = psSlice(dict_tables.pre_off[pid], dict_tables.pre_len[pid]);
            if (p + pre.len + 4 > limit) continue;
            if (!std.mem.eql(u8, data[p..][0..pre.len], pre)) continue;
            found = self.findAfter(data, p, p + pre.len, limit, pid, out, found);
        }
        return found;
    }

    /// `find` for one prefix id whose prefix `data[p..q)` is.
    fn findAfter(self: *const DictSearch, data: []const u8, p: usize, q: usize, limit: usize, pid: u8, out: *[max_dict_cands]DictCand, found_in: usize) usize {
        var found = found_in;
        if (q + 4 > limit or found == max_dict_cands) return found;
        const forms = &dict_tables.forms[pid];
        const at = &dict_tables.at[pid];
        const pre_len = q - p;
        const key = fold4(data[q..][0..4]);
        var w = self.heads[bucket(key)];
        while (w != 0) : (w = self.next[w - 1]) {
            if (self.wkey[w - 1] != key) continue;
            const n: usize = self.wlen[w - 1];
            const idx: usize = self.widx[w - 1];
            const word = dictionary.data[dictionary.offsets_by_length[n] + idx * n ..][0..n];
            const cmp = @min(n, limit - q);
            // How far the bytes are the word as it is, with its first letter
            // a capital, and in capitals (ASCII; `transformWord` confirms).
            const same = commonLen(word[0..cmp], data[q..][0..cmp]);
            const first_up = word[0] >= 'a' and word[0] <= 'z' and data[q] == word[0] - 32;
            var rest_len: usize = 0;
            var all_len: usize = 0;
            if (first_up) {
                rest_len = 1 + commonLen(word[1..cmp], data[q + 1 ..][0 .. cmp - 1]);
                all_len = 1;
                while (all_len < cmp) : (all_len += 1) {
                    const c = word[all_len];
                    const up = if (c >= 'a' and c <= 'z') c - 32 else c;
                    if (data[q + all_len] != up) break;
                }
            } else if (same < 4) continue;
            // A form fits when the bytes match the `m = n - cut` it keeps:
            // only the cuts from `n - have` on, and every form keeps 4.
            for ([3]usize{ same, rest_len, all_len }, 0..) |have, u| {
                if (have < 4) continue;
                const lo = n - @min(n, have);
                const hi = @min(n - 4, 9);
                if (lo > hi) continue;
                for (forms[at[u][lo]..at[u][hi + 1]]) |f| {
                    const m = n - f.omit;
                    const wl = pre_len + m + f.suf_len;
                    if (wl < min_dict_out or p + wl > limit) continue;
                    if (!std.mem.eql(u8, data[q + m ..][0..f.suf_len], psSlice(f.suf_off, f.suf_len))) continue;
                    if (f.upper != .none) {
                        // The decoder's own transform decides (UTF-8 upper-casing).
                        var tmp: [transforms.maxOutputLen(dictionary.max_word_length)]u8 = undefined;
                        const got = transforms.transformWord(&tmp, word, n, f.t);
                        if (got != wl or !std.mem.eql(u8, tmp[0..got], data[p..][0..got])) continue;
                    }
                    out[found] = .{ .n = @intCast(n), .wl = @intCast(wl), .t = f.t, .idx = @intCast(idx) };
                    found += 1;
                    if (found == max_dict_cands) return found;
                }
            }
        }
        return found;
    }

    fn commonLen(a: []const u8, b: []const u8) usize {
        var i: usize = 0;
        while (i < a.len and a[i] == b[i]) i += 1;
        return i;
    }
};

/// Where a copy ends on the cheapest path found to it (or the block's start,
/// node 0): the copy, and the literals before it, which start at the node
/// before (`from - ins`).
const OptNode = struct {
    cost: f32,
    /// The copy's start.
    from: u32,
    dist: u32,
    /// Literals before the copy.
    ins: u32,
    /// The nearest node on the path back from here (this one included)
    /// whose copy pushed its distance into the ring; 0 for none (google's
    /// `shortcut`). Set when the node is final.
    shortcut: u32 = 0,
    /// Copy length (what a word's transform produces).
    len: u16,
    /// A dictionary word's length; 0 for a copy.
    word: u8 = 0,
    /// The copy pushed its distance (not short code 0, not a word).
    pushed: bool = false,
};

/// google `ComputeMinimumCopyLength`: no copy from position `i` costs less
/// than a start's cost plus a bit for each length code bucket passed, so
/// the lengths whose end is already reached for that little are not tried.
/// The starts come cheapest first, so one walk serves them all: each goes
/// on from where the one before stopped.
const MinCopyLen = struct {
    len: u32 = min_ring_match,
    added: f32 = 0,
    bucket: u32 = 4,
    next_offset: u32 = 10,

    fn at(w: *MinCopyLen, nodes: []const OptNode, i: usize, cost: f32) u32 {
        while (i + w.len < nodes.len and nodes[i + w.len].cost <= cost + w.added) {
            w.len += 1;
            if (w.len == w.next_offset) {
                w.added += 1;
                w.next_offset += w.bucket;
                w.bucket *= 2;
            }
        }
        return w.len;
    }
};

/// Where copies are relaxed from: a start node's cost with the literals
/// since it (`ins` of them), and the ring there.
const OptSrc = struct { cost: f32, ins: u32, ring: [4]u32 };

/// google `StartPosQueue`: the eight nodes from which a copy at the
/// current position is cheapest, literals between included (`diff`: the
/// node's cost less the literal prices before it).
/// Starts a position's copies are tried from: google's five at quality 11,
/// all eight of the queue on a block that looks binary (`font_like` 1.6 %
/// smaller, fonts 0.4–0.6 %; text, html and json the same size for 13 %
/// more time).
const max_starts = 5;
const max_starts_binary = StartQueue.size;

/// A copy at a short code's distance (`code`), `l` bytes long.
const RingHit = struct { code: u8, d: u32, l: u32 };

/// The copies at a ring's sixteen short-code distances from one position:
/// each whose first two bytes match, in code order, with its length.
const RingProbe = struct {
    ring: [4]u32,
    n: u8 = 0,
    hits: [16]RingHit = undefined,
};

const KnownShort = enum(u16) { none = 0xfffe, unknown = 0xffff, _ };

/// Relax one start's ring copies (`RingProbe.hits`, in code order) from
/// node `i`: a length an earlier code reached is not tried again at a later
/// one (google's `best_len` in `UpdateNodes`), so a distance met twice is
/// skipped too. Returns the longest copy taken whole, or 0.
inline fn relaxRingHits(nodes: []OptNode, costs: *const OptCosts, nd: OptSrc, ic: LenCode, i: usize, hits: []const RingHit, min_len: u32, da: DistAlphabet) u32 {
    var take: u32 = 0;
    var best_len: u32 = min_len - 1;
    for (hits) |h| {
        if (h.l <= best_len) continue;
        const whole = h.l >= max_take_len;
        relaxCopies(nodes, costs, nd, ic, i, if (whole) h.l else best_len + 1, h.l, h.d, da, @enumFromInt(h.code));
        best_len = h.l;
        if (whole) take = @max(take, h.l);
    }
    return take;
}

const StartQueue = struct {
    const size = 8;
    items: [size]struct { at: u32, diff: f64, ring: [4]u32 } = undefined,
    len: usize = 0,

    fn takes(q: *const StartQueue, diff: f64) bool {
        return q.len < size or diff < q.items[size - 1].diff;
    }

    fn push(q: *StartQueue, at: u32, diff: f64, ring: [4]u32) void {
        var k = q.len;
        if (k == size) {
            if (diff >= q.items[size - 1].diff) return;
            k = size - 1;
        } else q.len += 1;
        while (k > 0 and q.items[k - 1].diff > diff) : (k -= 1) q.items[k] = q.items[k - 1];
        q.items[k] = .{ .at = at, .diff = diff, .ring = ring };
    }
};

const OptCosts = struct {
    cmd: [tables.num_command_symbols]f32,
    dist: [dist_contexts][dist_alphabet_max]f32,
    lit: [max_literal_trees][tables.num_literal_symbols]f32,
};

/// `-log2(share)` of each count; a count of zero costs `unseen_extra_bits`
/// more than a share of one in the total.
fn bitsOf(counts: []const u32, out: []f32, flat: f32) void {
    var total: u64 = 0;
    for (counts) |c| total += c;
    if (total == 0) {
        @memset(out, flat);
        return;
    }
    const lt = @log2(@as(f32, @floatFromInt(total)));
    for (counts, out) |c, *o| o.* = if (c == 0) lt + unseen_extra_bits else lt - @log2(@as(f32, @floatFromInt(c)));
}

/// Prices from `cmds`: the symbols a block of them would use, as
/// `writeCompressedBlock` resolves them.
fn fitCosts(gpa: std.mem.Allocator, costs: *OptCosts, cmds: []const Cmd, ring0: DistRing, da: DistAlphabet, model: *const LiteralModel) std.mem.Allocator.Error!void {
    const cmd_h = try gpa.alloc(u32, tables.num_command_symbols);
    defer gpa.free(cmd_h);
    @memset(cmd_h, 0);
    var dist_h: [dist_contexts][dist_alphabet_max]u32 = @splat(@splat(0));
    var ring = ring0;
    for (cmds) |c| {
        const ic = lengthCode(&cmd_tables.insert_off, &cmd_tables.insert_nbits, c.insert_len) orelse continue;
        const cl: u32 = if (c.copy_len == 0) cmd_tables.copy_off[0] else c.copy_len;
        const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, cl) orelse continue;
        // A dictionary word is never named by a short code and leaves the
        // ring alone.
        const short: ?u16 = if (c.copy_len != 0 and c.out_len == 0) ring.shortCode(c.dist) else null;
        const implicit = cmd_tables.implicit[ic.code][cc.code];
        const use_implicit = implicit != 0xffff and (c.copy_len == 0 or short == 0);
        cmd_h[if (use_implicit) implicit else cmd_tables.sym[ic.code][cc.code]] += 1;
        if (c.copy_len != 0) {
            if (!use_implicit) {
                const s = short orelse (da.code(c.dist) orelse continue).sym;
                dist_h[distContext(c.copy_len)][s] += 1;
            }
            if (c.out_len == 0) ring.update(c.dist, short);
        }
    }
    bitsOf(cmd_h, &costs.cmd, 8);
    for (&dist_h, &costs.dist) |*h, *o| bitsOf(h[0..da.n], o[0..da.n], 6);
    for (model.counts[0..model.ntrees], 0..) |*h, t| bitsOf(h, &costs.lit[t], 8);
}

/// Relax the copies of lengths `lo..hi` (inclusive) at distance `d` from
/// position `i`, reached as `nd` says: a start node's cost and ring with the
/// `nd.ins` literals since it (their code `ic`). One command each.
fn relaxCopies(
    nodes: []OptNode,
    costs: *const OptCosts,
    nd: OptSrc,
    ic: LenCode,
    i: usize,
    lo: u32,
    hi: u32,
    d: u32,
    da: DistAlphabet,
    /// `d`'s short code in `nd.ring` when the caller knows it (`.unknown`:
    /// looked up here).
    known: KnownShort,
) void {
    const short: ?u16 = switch (known) {
        .unknown => (DistRing{ .last = nd.ring }).shortCode(d),
        .none => null,
        _ => @intFromEnum(known),
    };
    var dist_bits: [dist_contexts]f32 = undefined;
    if (short) |s| {
        for (&dist_bits, &costs.dist) |*b, *row| b.* = row[s];
    } else {
        const dc = da.code(d) orelse return;
        for (&dist_bits, &costs.dist) |*b, *row| b.* = row[dc.sym] + @as(f32, @floatFromInt(dc.nbits));
    }
    const pushed = d != nd.ring[0];
    // One price per copy length code: the lengths it covers differ only in
    // their extra bits' value (the distance context is the same throughout:
    // the codes below 5 cover one length each).
    var l = lo;
    while (l <= hi) {
        const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, l) orelse {
            l += 1;
            continue;
        };
        const last = @min(hi, cmd_tables.copy_off[cc.code] + (@as(u32, 1) << cc.nbits) - 1);
        const implicit = cmd_tables.implicit[ic.code][cc.code];
        var bits: f32 = @floatFromInt(@as(u32, ic.nbits) + cc.nbits);
        if (implicit != 0xffff and short == 0) {
            bits += costs.cmd[implicit];
        } else {
            bits += costs.cmd[cmd_tables.sym[ic.code][cc.code]] + dist_bits[distContext(l)];
        }
        const c = nd.cost + bits;
        while (l <= last) : (l += 1) {
            const t = &nodes[i + l];
            if (c < t.cost) t.* = .{ .cost = c, .from = @intCast(i), .len = @intCast(l), .dist = d, .ins = nd.ins, .pushed = pushed };
        }
    }
}

/// Relax the dictionary word `dc` at node `i`, named by the distance `d`.
fn relaxWord(nodes: []OptNode, costs: *const OptCosts, nd: OptSrc, ic: LenCode, i: usize, dc: DictCand, d: u32, da: DistAlphabet) void {
    const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, dc.n) orelse return;
    const dcode = da.code(d) orelse return;
    const bits = @as(f32, @floatFromInt(@as(u32, ic.nbits) + cc.nbits + dcode.nbits)) +
        costs.cmd[cmd_tables.sym[ic.code][cc.code]] + costs.dist[distContext(dc.n)][dcode.sym];
    const c = nd.cost + bits;
    const t = &nodes[i + dc.wl];
    if (c < t.cost) t.* = .{ .cost = c, .from = @intCast(i), .len = dc.wl, .dist = d, .ins = nd.ins, .word = dc.n };
}

/// A copy `greedyParse` chose and its estimated saving in bits.
const Pick = struct { len: u32, dist: u32, gain: f32 };

/// A greedy, one-step-lazy parse over the candidates `collect` found: what
/// `buildCommands` makes, without a match finder of its own. The first
/// contender of `.q11` (a small block is often best served by it) and the
/// prices of the next.
fn greedyParse(
    gpa: std.mem.Allocator,
    data: []const u8,
    start: usize,
    end: usize,
    x: History,
    max_dist: usize,
    offs: []const u32,
    cands: []const Cand,
    ring0: DistRing,
    out: *std.ArrayListUnmanaged(Cmd),
) std.mem.Allocator.Error!void {
    const lit_cost = literalCost(data[start..end], 1);
    var ring = ring0;
    var p = start;
    var lit_start = start;
    var pending: ?Pick = null;
    while (p < end) {
        const here: ?Pick = pending orelse bestAt(data, start, end, x, max_dist, offs, cands, &ring, p, lit_cost);
        pending = null;
        const m = here orelse {
            p += 1;
            continue;
        };
        if (p + 1 < end) {
            if (bestAt(data, start, end, x, max_dist, offs, cands, &ring, p + 1, lit_cost)) |b| {
                if (b.gain > m.gain + lit_cost) {
                    pending = b;
                    p += 1;
                    continue;
                }
            }
        }
        try out.append(gpa, .{ .insert_len = @intCast(p - lit_start), .copy_len = m.len, .dist = m.dist });
        if (m.dist != ring.last[0]) ring.update(m.dist, null);
        p += m.len;
        lit_start = p;
    }
    if (lit_start < end) try out.append(gpa, .{ .insert_len = @intCast(end - lit_start), .copy_len = 0, .dist = 0 });
}

/// The candidate at `p` that saves the most bits (`Matcher.gain`'s estimate),
/// or a copy at one of the ring's two last distances.
fn bestAt(
    data: []const u8,
    start: usize,
    end: usize,
    x: History,
    max_dist: usize,
    offs: []const u32,
    cands: []const Cand,
    ring: *const DistRing,
    p: usize,
    lit_cost: f32,
) ?Pick {
    var best: ?Pick = null;
    var best_gain: f32 = 0;
    const max_len = @min(end - p, max_match);
    const reach = x.outMax(p, max_dist);
    if (p + 4 <= end) {
        const head: u32 = std.mem.readInt(u32, data[p..][0..4], .little) & 0xffff;
        for (ring.last[0..2], 0..) |d, i| {
            if (d == 0 or d > reach) continue;
            if (std.mem.readInt(u32, data[p - d ..][0..4], .little) & 0xffff != head) continue;
            const l = Matcher.matchLen(data, p - d, p, max_len);
            if (l < min_ring_match) continue;
            const g = @as(f32, @floatFromInt(l)) * lit_cost - @as(f32, if (i == 0) 3 else 5);
            if (g > best_gain) {
                best_gain = g;
                best = .{ .len = @intCast(l), .dist = d, .gain = g };
            }
        }
    }
    for (cands[offs[p - start]..offs[p - start + 1]]) |c| {
        const dist_bits: f32 = @floatFromInt(std.math.log2_int(u32, c.dist));
        const g = @as(f32, @floatFromInt(c.len)) * lit_cost - dist_bits - 6;
        if (g > best_gain) {
            best_gain = g;
            best = .{ .len = c.len, .dist = c.dist, .gain = g };
        }
    }
    return best;
}

/// The shortest-path parse of `data[start..end)` for `.q11`: `max_parses`
/// passes, each priced from the commands of the one before. Matches may reach
/// back before `start` but never past `end`.
fn buildCommandsOptimal(
    comptime px: bool,
    /// Lookups skip slots by tag (`Matcher.tagsPay`).
    comptime tagged: bool,
    /// The parses' lists (`parses`).
    gpa: std.mem.Allocator,
    /// Everything else, freed before return (`Core.tempAlloc`).
    tmp: std.mem.Allocator,
    matcher: *Matcher,
    start: usize,
    end: usize,
    max_dist: usize,
    ring0: DistRing,
    n_dist: usize,
    dsearch: *const DictSearch,
    parses: *[max_parses]std.ArrayListUnmanaged(Cmd),
) std.mem.Allocator.Error!void {
    const n = end - start;
    const x = matcher.history;
    const data = matcher.data;

    // Every position's candidates, found once. A copy of `max_take_len` is
    // taken whole, so the positions inside it get none.
    const offs = try tmp.alloc(u32, n + 1);
    defer tmp.free(offs);
    var cands: std.ArrayListUnmanaged(Cand) = .empty;
    defer cands.deinit(tmp);
    var buf: [max_cands]Cand = undefined;
    const doffs = try tmp.alloc(u32, n + 1);
    defer tmp.free(doffs);
    var dcands: std.ArrayListUnmanaged(DictCand) = .empty;
    defer dcands.deinit(tmp);
    var dbuf: [max_dict_cands]DictCand = undefined;
    // The nearest copies of 2 and of 3 bytes (google's H10 finds them, by
    // a scan of the last 64 bytes and its tree): shorter than any bucket
    // names. The last position of each 2-byte value and of each 3-byte
    // hash (checked) in this block.
    const near = try tmp.alloc([2]u32, n);
    defer tmp.free(near);
    @memset(near, .{ 0, 0 });
    const last2 = try tmp.alloc(u32, 1 << 16);
    defer tmp.free(last2);
    @memset(last2, 0);
    const last3 = try tmp.alloc(u32, 1 << 16);
    defer tmp.free(last3);
    @memset(last3, 0);
    const H = struct {
        fn k3(d: []const u8, q: usize) usize {
            const v: u32 = @as(u32, d[q]) | @as(u32, d[q + 1]) << 8 | @as(u32, d[q + 2]) << 16;
            return (v *% 0x9E3779B1) >> 16;
        }
        fn k2(d: []const u8, q: usize) usize {
            return @as(usize, d[q]) | @as(usize, d[q + 1]) << 8;
        }
        fn put(d: []const u8, q: usize, e: usize, l2: []u32, l3: []u32) void {
            if (q + 2 <= e) l2[k2(d, q)] = @intCast(q + 1);
            if (q + 3 <= e) l3[k3(d, q)] = @intCast(q + 1);
        }
    };
    var p = start;
    while (p < end) {
        offs[p - start] = @intCast(cands.items.len);
        doffs[p - start] = @intCast(dcands.items.len);
        if (p + 3 <= end) {
            const lim = x.outMax(p, max_dist);
            const nr = &near[p - start];
            const a2 = last2[H.k2(data, p)];
            if (a2 != 0 and p - (a2 - 1) <= lim) nr[0] = @intCast(p - (a2 - 1));
            const a3 = last3[H.k3(data, p)];
            if (a3 != 0 and p - (a3 - 1) <= lim and std.mem.eql(u8, data[a3 - 1 ..][0..3], data[p..][0..3])) nr[1] = @intCast(p - (a3 - 1));
        }
        H.put(data, p, end, last2, last3);
        const found = matcher.collect(px, tagged, p, x.outMax(p, max_dist), end, &buf);
        try cands.appendSlice(tmp, buf[0..found]);
        var step: usize = 1;
        if (found > 0 and buf[found - 1].len >= max_take_len) {
            step = buf[found - 1].len;
        } else {
            const d = dsearch;
            // Only words longer than the longest copy (google's H10 asks
            // the dictionary for those): a copy that long is the cheaper.
            const best: usize = if (found > 0) buf[found - 1].len else 0;
            if (best < transforms.maxOutputLen(dictionary.max_word_length)) {
                const nd = d.find(data, p, end, &dbuf);
                for (dbuf[0..nd]) |dc| {
                    if (dc.wl > best) try dcands.append(tmp, dc);
                }
            }
        }
        matcher.insert(p);
        var q = p + 1;
        while (q < p + step) : (q += 1) {
            offs[q - start] = @intCast(cands.items.len);
            doffs[q - start] = @intCast(dcands.items.len);
            matcher.insert(q);
            H.put(data, q, end, last2, last3);
        }
        p += step;
    }
    offs[n] = @intCast(cands.items.len);
    doffs[n] = @intCast(dcands.items.len);

    const nodes = try tmp.alloc(OptNode, n + 1);
    defer tmp.free(nodes);
    const lit_cost = try tmp.alloc(f32, n);
    defer tmp.free(lit_cost);
    const lit_pre = try tmp.alloc(f64, n + 1);
    defer tmp.free(lit_pre);
    const model = try tmp.create(LiteralModel);
    defer tmp.destroy(model);
    const costs = try tmp.create(OptCosts);
    defer tmp.destroy(costs);

    // The first parse: greedy, by the saving per candidate.
    parses[0].clearRetainingCapacity();
    try greedyParse(gpa, data, start, end, x, max_dist, offs, cands.items, ring0, &parses[0]);

    const inf = std.math.inf(f32);
    const starts: usize = if (looksBinary(data[start..end])) max_starts_binary else max_starts;
    var da: DistAlphabet = .{ .n = n_dist };
    var pass: usize = 1;
    while (pass < max_parses) : (pass += 1) {
        const out = &parses[pass];
        out.clearRetainingCapacity();
        const prev = parses[pass - 1].items;
        try chooseLiteralModel(tmp, CmdLiterals{ .input = data, .start = start, .cmds = prev }, .q11, model);
        // Distances priced with the NPOSTFIX/NDIRECT the block writer would
        // choose for the commands before (Ethiopic font −0.4 %).
        if (n_dist == dist_alphabet_size) {
            const dp = chooseDistParams(prev, ring0);
            da = .{ .p = dp, .n = dp.alphabet() };
        }
        try fitCosts(tmp, costs, prev, ring0, da, model);
        for (model.counts[0..model.ntrees], 0..) |*h, t| bitsOf(h, &costs.lit[t], 8);
        for (lit_cost, 0..) |*lc, i| {
            const q = start + i;
            const p1: u8 = if (q >= 1) data[q - 1] else 0;
            const p2: u8 = if (q >= 2) data[q - 2] else 0;
            lc.* = costs.lit[model.map[contextId(model.mode, p1, p2)]][data[q]];
        }

        lit_pre[0] = 0;
        for (lit_cost, 0..) |lc, i| lit_pre[i + 1] = lit_pre[i] + lc;

        // google's zopfli: a node is where a copy ends (or the block's
        // start); the literals after it are paid by the copy that follows,
        // from whichever of the `StartQueue`'s nodes is cheapest with them.
        // Each start brings its own ring, so a copy at a ring distance of a
        // path that is not the cheapest one here is still found.
        for (nodes) |*nd| nd.cost = inf;
        nodes[0] = .{ .cost = 0, .from = 0, .len = 0, .dist = 0, .ins = 0 };
        var queue: StartQueue = .{};
        var best_end: usize = 0;
        var best_end_cost: f64 = lit_pre[n];
        var i: usize = 0;
        while (i < n) {
            if (nodes[i].cost != inf) {
                const nd = &nodes[i];
                if (i > 0) nd.shortcut = if (nd.pushed) @intCast(i) else nodes[nd.from - nd.ins].shortcut;
                const diff = @as(f64, nd.cost) - lit_pre[i];
                if (queue.takes(diff)) {
                    // google `ComputeDistanceCache`: the ring from the
                    // path's last four pushed distances.
                    var ring = ring0.last;
                    var got: usize = 0;
                    var q = nd.shortcut;
                    while (got < 4 and q > 0) : (got += 1) {
                        ring[got] = nodes[q].dist;
                        q = nodes[nodes[q].from - nodes[q].ins].shortcut;
                    }
                    if (got < 4) @memcpy(ring[got..], ring0.last[0 .. 4 - got]);
                    queue.push(@intCast(i), diff, ring);
                }
                if (diff + lit_pre[n] < best_end_cost) {
                    best_end_cost = diff + lit_pre[n];
                    best_end = i;
                }
            }
            const pos = start + i;
            const reach = x.outMax(pos, max_dist);
            const max_len = @min(end - pos, max_match);
            var take: u32 = 0;
            var walk: MinCopyLen = .{};
            var probed: [StartQueue.size]RingProbe = undefined;
            var n_probed: usize = 0;
            for (queue.items[0..@min(queue.len, starts)], 0..) |st, k| {
                const ins = i - st.at;
                const ic = lengthCode(&cmd_tables.insert_off, &cmd_tables.insert_nbits, @intCast(ins)) orelse continue;
                const ring = st.ring;
                const nd: OptSrc = .{ .cost = @floatCast(st.diff + lit_pre[i]), .ins = @intCast(ins), .ring = ring };
                const min_len = walk.at(nodes, i, nd.cost);
                // The ring's distances and their neighbours (the sixteen
                // short codes), from every start.
                if (pos + 4 <= end) {
                    // Most starts share a ring with a cheaper one (three in
                    // four on html): its copies are found once per position.
                    const rp = for (probed[0..n_probed]) |*pr| {
                        if (@reduce(.And, @as(@Vector(4, u32), pr.ring) == @as(@Vector(4, u32), ring))) break pr;
                    } else blk: {
                        const pr = &probed[n_probed];
                        n_probed += 1;
                        pr.* = .{ .ring = ring };
                        const head: u32 = std.mem.readInt(u32, data[pos..][0..4], .little) & 0xffff;
                        inline for (0..16) |code| {
                            const dv: i64 = if (code < 4) ring[code] else @as(i64, ring[(code - 4) / 6]) + DistRing.deltas[(code - 4) % 6];
                            if (dv > 0 and dv <= reach) {
                                const d: u32 = @intCast(dv);
                                const c = pos - d;
                                if (std.mem.readInt(u32, data[c..][0..4], .little) & 0xffff == head) {
                                    pr.hits[pr.n] = .{ .code = code, .d = d, .l = @intCast(Matcher.matchLen(data, c, pos, max_len)) };
                                    pr.n += 1;
                                }
                            }
                        }
                        break :blk pr;
                    };
                    take = @max(take, relaxRingHits(nodes, costs, nd, ic, i, rp.hits[0..rp.n], min_len, da));
                }
                // Other distances from the two cheapest starts only (google:
                // more starts find new ring copies, not new copies).
                if (k >= 2) continue;
                var prev_len: u32 = @max(min_match, min_len) - 1;
                for (cands.items[offs[i]..offs[i + 1]]) |cd| {
                    if (cd.len <= prev_len) continue;
                    const whole = cd.len >= max_take_len;
                    relaxCopies(nodes, costs, nd, ic, i, if (whole) cd.len else prev_len + 1, cd.len, cd.dist, da, .unknown);
                    prev_len = cd.len;
                    if (whole) take = @max(take, cd.len);
                }
                for (near[i], 0..) |d, nk| {
                    if (d == 0) continue;
                    const l: u32 = @intCast(2 + nk);
                    if (l >= min_len) relaxCopies(nodes, costs, nd, ic, i, l, l, d, da, .unknown);
                }
                for (dcands.items[doffs[i]..doffs[i + 1]]) |dc| {
                    if (i + dc.wl > n) continue;
                    const word_id: u32 = dc.idx + (@as(u32, dc.t) << @intCast(dictionary.size_bits_by_length[dc.n]));
                    relaxWord(nodes, costs, nd, ic, i, dc, @intCast(reach + matcher.dict_len + 1 + word_id), da);
                }
            }
            // Past the inside of a copy taken whole — unless it could not be
            // named, and the node after it was not reached.
            i += if (take != 0 and nodes[i + take].cost != inf) take else 1;
        }
        if (nodes[n].cost != inf and nodes[n].cost <= best_end_cost) best_end = n;

        // The path from its end back: each node names its copy and the
        // insert before it, which starts at the node before.
        var at: usize = best_end;
        while (at > 0) {
            const nd = nodes[at];
            try out.append(gpa, if (nd.word != 0)
                .{ .insert_len = nd.ins, .copy_len = nd.word, .dist = nd.dist, .out_len = nd.len }
            else
                .{ .insert_len = nd.ins, .copy_len = nd.len, .dist = nd.dist });
            at = nd.from - nd.ins;
        }
        std.mem.reverse(Cmd, out.items);
        if (best_end < n) try out.append(gpa, .{ .insert_len = @intCast(n - best_end), .copy_len = 0, .dist = 0 });
    }
}

/// Scratch for `clusterLiterals`, on the heap: ~100 KiB.
const ClusterScratch = struct {
    hist: [num_contexts][tables.num_literal_symbols]u32,
    sets: [num_contexts]SymbolSet,
    delta: [num_contexts][num_contexts]f64,
};

const LiteralModel = struct {
    mode: u2 = 0,
    /// Context id -> literal code.
    map: [num_contexts]u8 = @splat(0),
    ntrees: u8 = 1,
    /// One histogram per literal code.
    counts: [max_literal_trees][tables.num_literal_symbols]u32 = @splat(@splat(0)),
    /// Every literal of the block in one histogram (the one-code model).
    single: [tables.num_literal_symbols]u32 = @splat(0),
};

fn contextId(mode: u2, p1: u8, p2: u8) u6 {
    const lut = tables.context_lookup[@as(usize, mode) * 512 ..][0..512];
    return @intCast(lut[p1] | lut[256 + @as(usize, p2)]);
}

/// `n * log2(n)` for small counts, where most of a context's counts fall.
const nlog2n_table: [4096]f32 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [4096]f32 = undefined;
    t[0] = 0;
    for (1..4096) |i| {
        const x: f64 = @floatFromInt(i);
        t[i] = @floatCast(x * @log2(x));
    }
    break :blk t;
};

fn nlog2n(n: u64) f64 {
    if (n < nlog2n_table.len) return nlog2n_table[@intCast(n)];
    const x: f64 = @floatFromInt(n);
    return x * @log2(x);
}

/// Estimated bits to code `h` with its own prefix code: the entropy of the
/// counts (`T log T - sum c log c`) plus a rough header price per used symbol.
fn histogramCost(h: *const [tables.num_literal_symbols]u32) f64 {
    var total: u64 = 0;
    var used: u32 = 0;
    var sum: f64 = 0;
    for (h) |c| {
        if (c == 0) continue;
        total += c;
        used += 1;
        sum += nlog2n(c);
    }
    if (total == 0) return 0;
    return nlog2n(total) - sum + 40 + 5 * @as(f64, @floatFromInt(used));
}

fn addInto(dst: *[tables.num_literal_symbols]u32, src: *const [tables.num_literal_symbols]u32) void {
    for (dst, src) |*d, x| d.* += x;
}

/// Which literals a histogram uses, as a 256-bit set.
const SymbolSet = [4]u64;

fn symbolSet(h: *const [tables.num_literal_symbols]u32) SymbolSet {
    var set: SymbolSet = @splat(0);
    for (h, 0..) |c, i| {
        if (c != 0) set[i >> 6] |= @as(u64, 1) << @intCast(i & 63);
    }
    return set;
}

/// `histogramCost(a + b)` without building the sum, walking only the
/// symbols either uses — a handful on small inputs, where clustering is
/// otherwise a fixed cost of 2016 pairs x 256 symbols per mode.
fn unionCost(a: *const [tables.num_literal_symbols]u32, b: *const [tables.num_literal_symbols]u32, sa: SymbolSet, sb: SymbolSet) f64 {
    var total: u64 = 0;
    var used: u32 = 0;
    var sum: f64 = 0;
    for (0..4) |w| {
        var bits = sa[w] | sb[w];
        while (bits != 0) {
            const i = w * 64 + @ctz(bits);
            bits &= bits - 1;
            const c: u64 = @as(u64, a[i]) + b[i];
            total += c;
            used += 1;
            sum += nlog2n(c);
        }
    }
    if (total == 0) return 0;
    return nlog2n(total) - sum + 40 + 5 * @as(f64, @floatFromInt(used));
}

/// The literals of a block's commands, in order, with the two bytes before
/// each (zeros before the output's start).
const CmdLiterals = struct {
    input: []const u8,
    start: usize,
    cmds: []const Cmd,

    inline fn each(s: CmdLiterals, ctx: anytype) void {
        var pos = s.start;
        for (s.cmds) |c| {
            for (0..c.insert_len) |k| {
                const q = pos + k;
                const p1: u8 = if (q >= 1) s.input[q - 1] else 0;
                const p2: u8 = if (q >= 2) s.input[q - 2] else 0;
                ctx.add(s.input[q], p1, p2);
            }
            pos += c.insert_len + c.produced();
        }
    }
};

/// The literals of one block type: the ranges `blocks` of the block's
/// literal sequence (`lits`, with the two bytes before each in `p1`/`p2`).
const RangeLiterals = struct {
    lits: []const u8,
    p1: []const u8,
    p2: []const u8,
    /// (first literal, count) per block of the type.
    blocks: []const [2]u32,

    inline fn each(s: RangeLiterals, ctx: anytype) void {
        for (s.blocks) |b| {
            for (b[0]..b[0] + b[1]) |i| ctx.add(s.lits[i], s.p1[i], s.p2[i]);
        }
    }
};

/// Literals from which the context mode is chosen by `contextCost` rather
/// than by clustering every mode.
const proxy_min_literals = 16384;

/// The entropy of the literals of `src` with a code per context of `mode`,
/// unclustered (no header costs).
fn contextCost(src: anytype, mode: u2, scratch: *ClusterScratch) f64 {
    const hist = &scratch.hist;
    // Not `@splat`: that is Zig 0.16's byte-wise `compiler_rt.memset`, 3 %
    // of `.q9` on a font (`Matcher.fillZero`).
    Matcher.fillZero(@as([*]u32, @ptrCast(hist))[0 .. num_contexts * tables.num_literal_symbols]);
    const Fill = struct {
        hist: *[num_contexts][tables.num_literal_symbols]u32,
        mode: u2,
        inline fn add(f: @This(), b: u8, p1: u8, p2: u8) void {
            f.hist[contextId(f.mode, p1, p2)][b] += 1;
        }
    };
    src.each(Fill{ .hist = hist, .mode = mode });
    var total: f64 = 0;
    for (hist) |*h| {
        var n: u64 = 0;
        var sum: f64 = 0;
        for (h) |c| {
            n += c;
            sum += nlog2n(c);
        }
        total += nlog2n(n) - sum;
    }
    return total;
}

/// Cluster the per-context histograms of `mode` for the literals of `src`
/// (`CmdLiterals` or `RangeLiterals`) and return the model with its
/// estimated cost.
fn clusterLiterals(src: anytype, mode: u2, scratch: *ClusterScratch, out: *LiteralModel) f64 {
    const hist = &scratch.hist;
    // Not `@splat`: that is Zig 0.16's byte-wise `compiler_rt.memset`, 3 %
    // of `.q9` on a font (`Matcher.fillZero`).
    Matcher.fillZero(@as([*]u32, @ptrCast(hist))[0 .. num_contexts * tables.num_literal_symbols]);
    const Fill = struct {
        hist: *[num_contexts][tables.num_literal_symbols]u32,
        mode: u2,
        inline fn add(f: @This(), b: u8, p1: u8, p2: u8) void {
            f.hist[contextId(f.mode, p1, p2)][b] += 1;
        }
    };
    src.each(Fill{ .hist = hist, .mode = mode });

    // Clusters start as the non-empty contexts.
    var cluster_of: [num_contexts]u8 = @splat(0);
    var members: [num_contexts]bool = @splat(false); // cluster id alive
    var cost: [num_contexts]f64 = @splat(0);
    var any = false;
    for (0..num_contexts) |i| {
        var nonempty = false;
        for (hist[i]) |c| {
            if (c != 0) nonempty = true;
        }
        cluster_of[i] = @intCast(i);
        members[i] = nonempty;
        if (nonempty) {
            cost[i] = histogramCost(&hist[i]);
            any = true;
        }
    }
    if (!any) {
        out.* = .{ .mode = mode };
        out.counts[0][0] = 1;
        return 0;
    }

    // Pairwise merge deltas, recomputed only for the merged cluster.
    const delta = &scratch.delta;
    const sets = &scratch.sets;
    for (0..num_contexts) |i| sets[i] = symbolSet(&hist[i]);
    for (0..num_contexts) |a| {
        for (a + 1..num_contexts) |b| {
            if (!members[a] or !members[b]) continue;
            delta[a][b] = unionCost(&hist[a], &hist[b], sets[a], sets[b]) - cost[a] - cost[b];
        }
    }
    var alive: usize = 0;
    for (members) |m| alive += @intFromBool(m);
    while (alive > 1) {
        var best: f64 = std.math.inf(f64);
        var ba: usize = 0;
        var bb: usize = 0;
        for (0..num_contexts) |a| {
            if (!members[a]) continue;
            for (a + 1..num_contexts) |b| {
                if (!members[b]) continue;
                if (delta[a][b] < best) {
                    best = delta[a][b];
                    ba = a;
                    bb = b;
                }
            }
        }
        // Stop when no merge saves bits and the cap is met.
        if (best >= 0 and alive <= max_literal_trees) break;
        addInto(&hist[ba], &hist[bb]);
        for (&sets[ba], sets[bb]) |*x, y| x.* |= y;
        cost[ba] = histogramCost(&hist[ba]);
        members[bb] = false;
        for (&cluster_of) |*c| {
            if (c.* == bb) c.* = @intCast(ba);
        }
        alive -= 1;
        for (0..num_contexts) |x| {
            if (x == ba or !members[x]) continue;
            const d = unionCost(&hist[ba], &hist[x], sets[ba], sets[x]) - cost[ba] - cost[x];
            if (x < ba) delta[x][ba] = d else delta[ba][x] = d;
        }
    }

    // Renumber the surviving clusters 0..ntrees-1.
    var renum: [num_contexts]u8 = @splat(0xff);
    var n: u8 = 0;
    var total: f64 = 0;
    out.* = .{ .mode = mode };
    for (0..num_contexts) |i| {
        if (!members[i]) continue;
        renum[i] = n;
        out.counts[n] = hist[i];
        total += cost[i];
        n += 1;
    }
    out.ntrees = n;
    for (0..num_contexts) |i| {
        // A context no literal used joins code 0; the map entry is free.
        out.map[i] = if (renum[cluster_of[i]] != 0xff) renum[cluster_of[i]] else 0;
    }
    // The context map itself: roughly two bits per entry beyond one tree.
    if (n > 1) total += 2 * num_contexts;
    return total;
}

/// The literal model for a block: context-free (one code) at `.q4`, or
/// when the literals are too few or too random for contexts to pay; else the
/// cheapest clustering over the UTF8, LSB6 and SIGNED context modes. SIGNED
/// wins on fonts (TTF: 1.2–2.2 % smaller than UTF8, 2026-10-15; google picks
/// it there too); MSB6 never won on anything measured, so it is not tried.
fn chooseLiteralModel(gpa: std.mem.Allocator, src: anytype, effort: Effort, out: *LiteralModel) std.mem.Allocator.Error!void {
    return chooseLiteralModelIn(gpa, null, src, effort, out);
}

/// `chooseLiteralModel` with the caller's scratch, if any (else one is
/// allocated when clustering is tried at all).
fn chooseLiteralModelIn(gpa: std.mem.Allocator, scratch_in: ?*ClusterScratch, src: anytype, effort: Effort, out: *LiteralModel) std.mem.Allocator.Error!void {
    out.* = .{};

    const Count = struct {
        h: *[tables.num_literal_symbols]u32,
        inline fn add(c: @This(), b: u8, _: u8, _: u8) void {
            c.h[b] += 1;
        }
    };
    src.each(Count{ .h = &out.counts[0] });
    var n_lits: u64 = 0;
    for (out.counts[0]) |c| n_lits += c;
    out.single = out.counts[0];
    if (effort.finder() != .deep or n_lits < 256) return;
    // Near 8 bits a literal: no context will find structure a single code
    // misses (random or already-compressed bytes).
    if (histogramCost(&out.counts[0]) > 7.9 * @as(f64, @floatFromInt(n_lits))) return;

    const scratch = scratch_in orelse try gpa.create(ClusterScratch);
    defer if (scratch_in == null) gpa.destroy(scratch);
    const single = histogramCost(&out.counts[0]);
    var best_cost = single;
    var trial: LiteralModel = undefined;
    // Literals that are nearly all ASCII: UTF8 alone (it won on every such
    // block measured — text, HTML, JSON — and clustering is a tenth of
    // `.q6`'s time per mode).
    var ascii: u64 = 0;
    for (out.single[0..0x80]) |c| ascii += c;
    if (ascii * 100 < n_lits * ascii_pct and n_lits < proxy_min_literals) {
        // Every mode is clustered — but a mode's unclustered entropy plus
        // the least any set of codes pays in headers (one code, every
        // symbol used once) is a floor under its clustered cost: merging
        // never lowers entropy. A mode whose floor is no better than the
        // best so far cannot win and is skipped, cheapest floor first. Same
        // choice as clustering all three; on fonts most modes go
        // (2026-10-15).
        var used: u32 = 0;
        for (out.single) |c| used += @intFromBool(c != 0);
        const header_floor = 40 + 5 * @as(f64, @floatFromInt(used));
        const order = [3]u2{ 2, 0, 3 };
        var floor: [3]f64 = undefined;
        for (order, &floor) |mode, *f| f.* = contextCost(src, mode, scratch) + header_floor;
        var by_floor = [3]u8{ 0, 1, 2 };
        std.mem.sort(u8, &by_floor, &floor, struct {
            fn lt(fl: *const [3]f64, a: u8, b: u8) bool {
                return fl[a] < fl[b] or (fl[a] == fl[b] and a < b);
            }
        }.lt);
        // Ties go to the mode listed first in `order`, as when all three
        // were clustered in that order; the one-code model wins those.
        var best_idx: u8 = 3;
        for (by_floor) |idx| {
            if (floor[idx] > best_cost or (floor[idx] == best_cost and (best_idx == 3 or idx > best_idx))) continue;
            const c = clusterLiterals(src, order[idx], scratch, &trial);
            if (c < best_cost or (c == best_cost and best_idx != 3 and idx < best_idx)) {
                best_cost = c;
                best_idx = idx;
                const all = out.single;
                out.* = trial;
                out.single = all;
            }
        }
        return;
    }
    var modes_buf: [1]u2 = .{2};
    const modes: []const u2 = if (ascii * 100 >= n_lits * ascii_pct) &.{2} else blk: {
        // Of UTF8, LSB6 and SIGNED, cluster only the one whose 64 context
        // histograms have the least entropy unclustered: clustering is most
        // of the model's time on binary data (a third of `.q6` on a
        // font). It picked what clustering all three picks on every
        // `.q6` block measured; below `proxy_min_literals` (where
        // clustering is cheap) it did not always.
        var best_mode: u2 = 2;
        var best_raw = std.math.inf(f64);
        for ([3]u2{ 2, 0, 3 }) |mode| {
            const raw = contextCost(src, mode, scratch);
            if (raw < best_raw) {
                best_raw = raw;
                best_mode = mode;
            }
        }
        modes_buf[0] = best_mode;
        break :blk &modes_buf;
    };
    for (modes) |mode| {
        const c = clusterLiterals(src, mode, scratch, &trial);
        if (c < best_cost) {
            best_cost = c;
            const all = out.single;
            out.* = trial;
            out.single = all;
        }
    }
}

fn writeVarLenUint8(w: *BitWriter, v: u8) std.mem.Allocator.Error!void {
    if (v == 0) return w.writeBits(0, 1);
    try w.writeBits(1, 1);
    const n: u3 = @intCast(std.math.log2_int(u8, v));
    try w.writeBits(n, 3);
    if (n != 0) try w.writeBits(v - (@as(u32, 1) << n), n);
}

/// NTREES and, above one tree, the map (RFC 7932 §7.3): of the two forms —
/// tree ids as they are, or move-to-front ranks (IMTF) — and RLEMAX 0 or
/// the longest run's code or one below (runs of zeros as one symbol),
/// whichever writes shortest. (Every RLEMAX was no shorter on the fonts and
/// text measured, and cost `.q6` 3 %.)
fn writeContextMap(gpa: std.mem.Allocator, w: *BitWriter, map: []const u8, ntrees: usize) GiveUp!void {
    try writeVarLenUint8(w, @intCast(ntrees - 1));
    if (ntrees == 1) return;
    const ranks = try gpa.alloc(u8, map.len);
    defer gpa.free(ranks);
    moveToFront(map, ranks);
    // Each try goes to `trial`, resumed at `w`'s bit; the shortest is kept
    // in `best` and spliced into `w` rather than written a last time.
    const at = w.mark();
    var trial = BitWriter{ .gpa = gpa };
    defer trial.buf.deinit(gpa);
    var best = BitWriter{ .gpa = gpa };
    defer best.buf.deinit(gpa);
    var best_bits: usize = std.math.maxInt(usize);
    for ([2]bool{ false, true }) |mtf| {
        // RLEMAX above the longest run's code only adds symbols.
        const top = longestZeroRunCode(if (mtf) ranks else map);
        for ([3]u5{ 0, top -| 1, top }, 0..) |rle, k| {
            if (k > 0 and rle == 0) continue;
            trial.resumeAt(at);
            try writeMapSymbols(gpa, &trial, if (mtf) ranks else map, ntrees, rle, mtf);
            if (trial.bitPos() < best_bits) {
                best_bits = trial.bitPos();
                std.mem.swap(BitWriter, &trial, &best);
            }
        }
    }
    try w.takeFrom(at, &best);
}

/// The move-to-front ranks of `map` (what the decoder's inverse transform
/// turns back into it).
fn moveToFront(map: []const u8, out: []u8) void {
    var order: [256]u8 = undefined;
    for (&order, 0..) |*o, i| o.* = @intCast(i);
    for (map, out) |v, *r| {
        const idx: u8 = @intCast(std.mem.indexOfScalar(u8, &order, v).?);
        r.* = idx;
        var j: usize = idx;
        while (j > 0) : (j -= 1) order[j] = order[j - 1];
        order[0] = v;
    }
}

/// The run-length code of the longest run of zeros in `vals` (0 for none
/// longer than one), capped at RLEMAX's 16.
fn longestZeroRunCode(vals: []const u8) u5 {
    var longest: usize = 0;
    var run: usize = 0;
    for (vals) |v| {
        run = if (v == 0) run + 1 else 0;
        longest = @max(longest, run);
    }
    if (longest < 2) return 0;
    return @intCast(@min(std.math.log2_int(usize, longest), 16));
}

/// RLEMAX, the code over `vals` (zero runs as codes 1..`rle`, a value v as
/// v + `rle`), the symbols, and the IMTF bit.
fn writeMapSymbols(gpa: std.mem.Allocator, w: *BitWriter, vals: []const u8, ntrees: usize, rle: u5, mtf: bool) GiveUp!void {
    if (rle == 0) {
        try w.writeBits(0, 1);
    } else {
        try w.writeBits(1, 1);
        try w.writeBits(rle - 1, 4);
    }
    const alphabet = ntrees + rle;
    var counts: [256 + 16]u32 = undefined;
    Matcher.fillZero(counts[0..alphabet]);
    var it: ZeroRuns = .{ .vals = vals, .rle = rle };
    while (it.next()) |sym| counts[sym.code] += 1;
    var code = try buildAndWriteCode(gpa, w, counts[0..alphabet], @intCast(alphabet));
    defer code.deinit(gpa);
    it = .{ .vals = vals, .rle = rle };
    while (it.next()) |sym| {
        try code.emit(w, sym.code);
        if (sym.nbits != 0) try w.writeBits(sym.extra, sym.nbits);
    }
    try w.writeBits(@intFromBool(mtf), 1);
}

/// The symbols of a context map with runs of zeros coded up to `rle`.
const ZeroRuns = struct {
    vals: []const u8,
    rle: u5,
    i: usize = 0,
    /// Zeros left of the current run.
    run: usize = 0,

    fn next(z: *ZeroRuns) ?struct { code: u16, extra: u32, nbits: u5 } {
        if (z.run == 0) {
            if (z.i == z.vals.len) return null;
            const v = z.vals[z.i];
            if (v != 0 or z.rle == 0) {
                z.i += 1;
                return .{ .code = if (v == 0) 0 else @as(u16, v) + z.rle, .extra = 0, .nbits = 0 };
            }
            while (z.i < z.vals.len and z.vals[z.i] == 0) : (z.i += 1) z.run += 1;
        }
        if (z.run == 1) {
            z.run = 0;
            return .{ .code = 0, .extra = 0, .nbits = 0 };
        }
        // Code k covers 2^k .. 2^(k+1) - 1 zeros.
        const k: u5 = @intCast(@min(std.math.log2_int(usize, z.run), z.rle));
        const take = @min(z.run, (@as(usize, 2) << k) - 1);
        z.run -= take;
        return .{ .code = k, .extra = @intCast(take - (@as(usize, 1) << k)), .nbits = k };
    }
};

// ---------------------------------------------------------------------------
// Meta-block writers.

/// One command resolved for writing: its symbol, extra bits and distance.
const Resolved = struct {
    sym: u16,
    insert_extra: u32,
    insert_nbits: u5,
    copy_extra: u32,
    copy_nbits: u5,
    dist_sym: u16,
    dist_extra: u32,
    dist_nbits: u5,
    has_dist: bool,
    /// The distance context (`distContext`) of the command's copy.
    dist_ctx: u2,
};

/// The codes and maps a meta-block's commands are written with.
const Layout = struct {
    lit_codes: []const Code,
    /// 64 entries per literal block type.
    lit_map: []const u8,
    lit_modes: []const u2,
    /// Every literal block type has one code for all its contexts: no
    /// context is computed (google/brotli's `literal_context_map_size == 0`).
    lit_per_type: bool = false,
    /// One per command block type.
    cmd_codes: []const Code,
    dist_codes: []const Code,
    /// Four entries per distance block type.
    dist_map: []const u8,
};

/// The commands of a meta-block, with block switches when `split`. Without,
/// the codes and maps are copied into locals: behind slices, every
/// `writeBits` (a store) made the compiler load them again per command —
/// `.q6` was 7 % slower in cycles (2026-10-15).
fn emitCommands(
    comptime split: bool,
    w: *BitWriter,
    input: []const u8,
    start: usize,
    cmds: []const Cmd,
    res: []const Resolved,
    blocks: *[3]BlockCodes,
    l: Layout,
) GiveUp!void {
    const cmd_code0 = l.cmd_codes[0];
    const lit_map0: [num_contexts]u8 = l.lit_map[0..num_contexts].*;
    const mode0 = l.lit_modes[0];
    const dist_map0: [dist_contexts]u8 = l.dist_map[0..dist_contexts].*;
    const one_literal_code = !split and l.lit_codes.len == 1;
    var lit_pos = start;
    for (cmds, res) |c, r| {
        if (split) {
            try blocks[1].step(w);
            try l.cmd_codes[blocks[1].cur()].emit(w, r.sym);
        } else {
            try cmd_code0.emit(w, r.sym);
        }
        if (r.insert_nbits != 0) try w.writeBits(r.insert_extra, r.insert_nbits);
        if (r.copy_nbits != 0) try w.writeBits(r.copy_extra, r.copy_nbits);
        const lits_here = input[lit_pos..][0..c.insert_len];
        if (one_literal_code) {
            // No context to look up; two codes of at most 15 bits fit one
            // `writeBits`.
            const code = l.lit_codes[0];
            var k: usize = 0;
            while (k + 2 <= lits_here.len) : (k += 2) {
                const l0: u5 = @intCast(code.len[lits_here[k]]);
                const l1: u5 = @intCast(code.len[lits_here[k + 1]]);
                try w.writeBits(@as(u32, code.bits[lits_here[k]]) | @as(u32, code.bits[lits_here[k + 1]]) << l0, @as(u6, l0) + l1);
            }
            if (k < lits_here.len) try code.emit(w, lits_here[k]);
        } else if (l.lit_per_type) {
            for (lits_here) |b| {
                if (split) try blocks[0].step(w);
                const t: usize = if (split) blocks[0].cur() else 0;
                try l.lit_codes[l.lit_map[t * num_contexts]].emit(w, b);
            }
        } else if (!split or blocks[0].split.ntypes == 1) {
            for (lit_pos..lit_pos + c.insert_len) |q| {
                const p1: u8 = if (q >= 1) input[q - 1] else 0;
                const p2: u8 = if (q >= 2) input[q - 2] else 0;
                try l.lit_codes[lit_map0[contextId(mode0, p1, p2)]].emit(w, input[q]);
            }
        } else {
            for (lit_pos..lit_pos + c.insert_len) |q| {
                try blocks[0].step(w);
                const t: usize = blocks[0].cur();
                const p1: u8 = if (q >= 1) input[q - 1] else 0;
                const p2: u8 = if (q >= 2) input[q - 2] else 0;
                try l.lit_codes[l.lit_map[t * num_contexts + contextId(l.lit_modes[t], p1, p2)]].emit(w, input[q]);
            }
        }
        lit_pos += c.insert_len;
        if (r.has_dist) {
            const tree = if (split) blk: {
                try blocks[2].step(w);
                break :blk l.dist_map[@as(usize, blocks[2].cur()) * dist_contexts + r.dist_ctx];
            } else dist_map0[r.dist_ctx];
            try l.dist_codes[tree].emit(w, r.dist_sym);
            if (r.dist_nbits != 0) try w.writeBits(r.dist_extra, r.dist_nbits);
        }
        lit_pos += c.produced();
    }
}

/// Write one compressed meta-block for `input[start..end)`.
fn writeCompressedBlock(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    input: []const u8,
    start: usize,
    end: usize,
    cmds: []const Cmd,
    is_last: bool,
    ring: *DistRing,
    effort: Effort,
    /// Context-free literals whatever the effort (the real-bits check in
    /// `compressWith`).
    single_literal_code: bool,
    env: BlockEnv,
) GiveUp!BlockResult {
    const n = end - start;
    if (n == 0 or n > max_store_block) return error.EncoderInvariant;
    if (cmds.len == 0) return error.EncoderInvariant;

    // --- resolve every command and histogram the three alphabets ------------
    const res = try gpa.alloc(Resolved, cmds.len);
    defer gpa.free(res);

    const cmd_counts = try gpa.alloc(u32, tables.num_command_symbols);
    defer gpa.free(cmd_counts);
    Matcher.fillZero(cmd_counts);
    if (env.large_window and (env.dist.npostfix != 0 or env.dist.ndirect != 0)) return error.EncoderInvariant;
    const n_dist: u32 = if (env.large_window) dist_alphabet_large else env.dist.alphabet();
    // Only the first `n_dist` of each row are used (64 of 520 for the
    // default parameters): zeroing whole rows here and below was most of
    // `.q6`'s memset on a 16 KiB font, `@memset` being byte-wise
    // (`Matcher.fillZero`).
    var dist_counts: [dist_contexts][dist_alphabet_max]u32 = undefined;
    for (&dist_counts) |*row| @memset(row[0..n_dist], 0);

    var covered: usize = 0;
    var lit_pos = start;
    for (cmds, 0..) |c, i| {
        const ic = lengthCode(&cmd_tables.insert_off, &cmd_tables.insert_nbits, c.insert_len) orelse
            return error.EncoderInvariant;
        // The final literals-only command still carries a copy code; the
        // cheapest is code 0 (offset 2, no extra bits).
        const cl: u32 = if (c.copy_len == 0) cmd_tables.copy_off[0] else c.copy_len;
        const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, cl) orelse
            return error.EncoderInvariant;
        // A copy at the last distance needs no distance symbol at all when
        // the lengths fit an implicit-distance command; the final
        // literals-only command reads no distance either way.
        const short: ?u16 = if (c.copy_len != 0 and c.out_len == 0) ring.shortCode(c.dist) else null;
        const implicit = cmd_tables.implicit[ic.code][cc.code];
        const use_implicit = implicit != 0xffff and (c.copy_len == 0 or short == 0);
        const sym = if (use_implicit) implicit else cmd_tables.sym[ic.code][cc.code];

        var r: Resolved = .{
            .sym = sym,
            .insert_extra = ic.extra,
            .insert_nbits = ic.nbits,
            .copy_extra = cc.extra,
            .copy_nbits = cc.nbits,
            .dist_sym = 0,
            .dist_extra = 0,
            .dist_nbits = 0,
            .has_dist = c.copy_len != 0 and !use_implicit,
            .dist_ctx = distContext(c.copy_len),
        };
        if (c.copy_len != 0) {
            if (c.out_len == 0) {
                if (c.dist == 0 or c.dist > lit_pos + c.insert_len + env.reach) return error.EncoderInvariant;
                ring.update(c.dist, short);
            } else {
                const at = lit_pos + c.insert_len;
                if (at + c.out_len > end) return error.EncoderInvariant;
                try checkWord(c, at + env.dropped, env, input[at..][0..c.out_len]);
            }
        }
        if (r.has_dist) {
            if (short) |code| {
                r.dist_sym = code;
            } else {
                const dc = distanceCodeWith(c.dist, env.dist, n_dist) orelse return error.EncoderInvariant;
                r.dist_sym = dc.sym;
                r.dist_extra = dc.extra;
                r.dist_nbits = dc.nbits;
            }
            dist_counts[r.dist_ctx][r.dist_sym] += 1;
        }
        res[i] = r;
        cmd_counts[sym] += 1;
        lit_pos += c.insert_len;
        covered += c.insert_len + c.produced();
        lit_pos += c.produced();
    }
    // MLEN must match the bytes the commands produce exactly, or the decoder
    // would run past the end of the meta-block.
    if (covered != n) return error.EncoderInvariant;

    // --- block splits and the literal model ---------------------------------
    // Literals, insert-and-copy symbols and distance symbols each cut into
    // blocks of a few types, each type with codes of its own (RFC 7932 §6):
    // a font's or a binary's sections differ. `.q6`/`.q9`: greedy, in one
    // pass, with static literal contexts (`greedy_split.zig`, google/brotli's
    // model for qualities 4–9); `.q11`: the iterative splitter and clustered
    // contexts; `.q4`: one type each and one literal code.
    var blocks: [3]BlockCodes = undefined;
    var n_blocks: usize = 0;
    defer for (blocks[0..n_blocks]) |*b| b.deinit(gpa);
    var lit_modes: []u2 = &.{};
    defer gpa.free(lit_modes);
    var lit_map: []u8 = &.{};
    defer gpa.free(lit_map);
    var lit_alloc: [][tables.num_literal_symbols]u32 = &.{};
    defer gpa.free(lit_alloc);
    var single_counts: [tables.num_literal_symbols]u32 = undefined;
    Matcher.fillZero(&single_counts);
    var lit_ntrees: usize = 0;
    if (effort == .q6 or effort == .q9) {
        // `single_literal_code`: one literal type and code (the real-bits
        // check in `compressWith`).
        const split_lits = !single_literal_code;
        const sc: greedy_split.StaticContexts = if (split_lits)
            greedy_split.chooseStaticContexts(input[start..end], effort.quality(), env.size_hint)
        else
            .{ .n = 1, .map = &greedy_split.map_single };
        var n_lits: usize = 0;
        var n_dsyms: usize = 0;
        for (cmds, res) |c, r| {
            n_lits += c.insert_len;
            n_dsyms += @intFromBool(r.has_dist);
        }
        // Minimum block sizes and new-type thresholds: google/brotli's.
        var lsp = try greedy_split.Splitter.init(gpa, tables.num_literal_symbols, sc.n, 512, 400, if (split_lits) n_lits else 0);
        defer lsp.deinit(gpa);
        var csp = try greedy_split.Splitter.init(gpa, tables.num_command_symbols, 1, 1024, 500, cmds.len);
        defer csp.deinit(gpa);
        var dsp = try greedy_split.Splitter.init(gpa, n_dist, 1, 512, 100, n_dsyms);
        defer dsp.deinit(gpa);
        var q = start;
        for (cmds, res) |c, r| {
            csp.add(r.sym, 0);
            if (split_lits) {
                var p1: u8 = if (q >= 1) input[q - 1] else 0;
                var p2: u8 = if (q >= 2) input[q - 2] else 0;
                for (input[q..][0..c.insert_len]) |b| {
                    lsp.add(b, sc.map[contextId(2, p1, p2)]);
                    p2 = p1;
                    p1 = b;
                }
            } else {
                for (input[q..][0..c.insert_len]) |b| single_counts[b] += 1;
            }
            if (r.has_dist) dsp.add(r.dist_sym, 0);
            q += c.insert_len + c.produced();
        }
        blocks[0] = try .init(gpa, if (split_lits) try lsp.finish(gpa) else try block_split.Split.single(gpa, n_lits));
        n_blocks = 1;
        blocks[1] = try .init(gpa, try csp.finish(gpa));
        n_blocks = 2;
        blocks[2] = try .init(gpa, try dsp.finish(gpa));
        n_blocks = 3;

        // UTF8 mode for every type; type t's contexts are codes
        // t * n .. t * n + n - 1, the splitter's histograms as they are.
        const nlt: usize = blocks[0].split.ntypes;
        lit_modes = try gpa.alloc(u2, nlt);
        @memset(lit_modes, 2);
        lit_map = try gpa.alloc(u8, nlt * num_contexts);
        if (split_lits) {
            lit_ntrees = nlt * sc.n;
            for (0..nlt) |t| {
                for (lit_map[t * num_contexts ..][0..num_contexts], sc.map) |*m, ctx| m.* = @intCast(t * sc.n + ctx);
            }
            lit_alloc = try gpa.alloc([tables.num_literal_symbols]u32, lit_ntrees);
            const hists: [*]const [tables.num_literal_symbols]u32 = @ptrCast(lsp.hist.ptr);
            @memcpy(lit_alloc, hists[0..lit_ntrees]);
            for (lit_alloc) |*h| addInto(&single_counts, h);
        } else {
            lit_ntrees = 1;
            @memset(lit_map, 0);
            lit_alloc = try gpa.alloc([tables.num_literal_symbols]u32, 1);
            lit_alloc[0] = single_counts;
        }
    } else {
        const split_on = effort == .q11;
        const rounds: u32 = 4;
        var n_lits: usize = 0;
        var n_dsyms: usize = 0;
        var ascii_lits: usize = 0;
        {
            var q = start;
            for (cmds, res) |c, r| {
                if (split_on) {
                    for (input[q..][0..c.insert_len]) |b| ascii_lits += @intFromBool(b < 0x80);
                }
                n_lits += c.insert_len;
                n_dsyms += @intFromBool(r.has_dist);
                q += c.insert_len + c.produced();
            }
        }
        // Literals are split only when not nearly all ASCII: on text, HTML and
        // JSON literal block types won nothing measurable (−0.2 % to +0.2 %)
        // for a tenth of `.q9`'s time; on fonts 3–6 %.
        const split_lits = split_on and !single_literal_code and ascii_lits * 100 < n_lits * ascii_pct;
        // The literal sequence, then the byte before each, then the one before
        // that (the context).
        const lits = try gpa.alloc(u8, if (split_lits) 3 * n_lits else 0);
        defer gpa.free(lits);
        if (split_lits) {
            var k: usize = 0;
            var q0 = start;
            for (cmds) |c| {
                for (q0..q0 + c.insert_len) |q| {
                    lits[k] = input[q];
                    lits[n_lits + k] = if (q >= 1) input[q - 1] else 0;
                    lits[2 * n_lits + k] = if (q >= 2) input[q - 2] else 0;
                    k += 1;
                }
                q0 += c.insert_len + c.produced();
            }
        }
        blocks[0] = try .init(gpa, if (split_lits)
            try block_split.split(u8, gpa, lits[0..n_lits], tables.num_literal_symbols, lit_split_params(rounds))
        else
            try block_split.Split.single(gpa, n_lits));
        n_blocks = 1;
        if (split_on) {
            const syms = try gpa.alloc(u16, @max(cmds.len, n_dsyms));
            defer gpa.free(syms);
            for (res, syms[0..cmds.len]) |r, *s| s.* = r.sym;
            blocks[1] = try .init(gpa, try block_split.split(u16, gpa, syms[0..cmds.len], tables.num_command_symbols, cmd_split_params(rounds)));
            n_blocks = 2;
            var k: usize = 0;
            for (res) |r| {
                if (!r.has_dist) continue;
                syms[k] = r.dist_sym;
                k += 1;
            }
            blocks[2] = try .init(gpa, try block_split.split(u16, gpa, syms[0..n_dsyms], n_dist, dist_split_params(rounds)));
            n_blocks = 3;
        } else {
            // `.q4`: one type each, no symbols to look at.
            blocks[1] = try .init(gpa, try block_split.Split.single(gpa, cmds.len));
            n_blocks = 2;
            blocks[2] = try .init(gpa, try block_split.Split.single(gpa, n_dsyms));
            n_blocks = 3;
        }
        const nlt: usize = blocks[0].split.ntypes;

        // --- literal model: per literal block type a context mode and map; the
        // codes are shared across types ------------------------------------------
        const model = try gpa.create(LiteralModel);
        defer gpa.destroy(model);
        lit_modes = try gpa.alloc(u2, nlt);
        lit_map = try gpa.alloc(u8, nlt * num_contexts);
        lit_alloc = if (nlt == 1) blk: {
            try chooseLiteralModel(gpa, CmdLiterals{ .input = input, .start = start, .cmds = cmds }, if (single_literal_code) .q4 else effort, model);
            lit_modes[0] = model.mode;
            @memcpy(lit_map, &model.map);
            const a = try gpa.alloc([tables.num_literal_symbols]u32, model.ntrees);
            @memcpy(a, model.counts[0..model.ntrees]);
            single_counts = model.single;
            lit_ntrees = model.ntrees;
            break :blk a;
        } else blk: {
            // Each type's own model — its own context mode and grouping — then
            // the codes of all types merged where one code serves several. (One
            // mode and grouping for all types, with a code per (type, group),
            // was 8 % faster at `.q9` but 0.2–0.5 % larger on fonts,
            // 2026-10-15.)
            const first_tree = try gpa.alloc(u32, nlt + 1);
            defer gpa.free(first_tree);
            const ranges = try gpa.alloc([2]u32, blocks[0].split.lens.len);
            defer gpa.free(ranges);
            const scratch = try gpa.create(ClusterScratch);
            defer gpa.destroy(scratch);
            var all: std.ArrayListUnmanaged([tables.num_literal_symbols]u32) = .empty;
            errdefer all.deinit(gpa);
            single_counts = @splat(0);
            const src_lits = lits[0..n_lits];
            const src_p1 = lits[n_lits..][0..n_lits];
            const src_p2 = lits[2 * n_lits ..][0..n_lits];
            for (0..nlt) |t| {
                var nr: usize = 0;
                var at: u32 = 0;
                for (blocks[0].split.types, blocks[0].split.lens) |bt, bl| {
                    if (bt == t) {
                        ranges[nr] = .{ at, bl };
                        nr += 1;
                    }
                    at += bl;
                }
                try chooseLiteralModelIn(gpa, scratch, RangeLiterals{ .lits = src_lits, .p1 = src_p1, .p2 = src_p2, .blocks = ranges[0..nr] }, effort, model);
                lit_modes[t] = model.mode;
                first_tree[t] = @intCast(all.items.len);
                @memcpy(lit_map[t * num_contexts ..][0..num_contexts], &model.map);
                try all.appendSlice(gpa, model.counts[0..model.ntrees]);
                addInto(&single_counts, &model.single);
            }
            const total: u32 = @intCast(all.items.len);
            const remap = try gpa.alloc(u32, total);
            defer gpa.free(remap);
            const flat = @as([*]u32, @ptrCast(all.items.ptr))[0 .. @as(usize, total) * tables.num_literal_symbols];
            lit_ntrees = try block_split.mergeHistograms(gpa, flat, tables.num_literal_symbols, total, 256, remap);
            for (0..nlt) |t| {
                for (lit_map[t * num_contexts ..][0..num_contexts]) |*m| m.* = @intCast(remap[first_tree[t] + m.*]);
            }
            break :blk try all.toOwnedSlice(gpa);
        };
    }
    const lt: usize = blocks[0].split.ntypes;
    const it: usize = blocks[1].split.ntypes;
    const dt: usize = blocks[2].split.ntypes;
    const lit_counts = lit_alloc[0..lit_ntrees];
    // Every code needs at least one symbol even when unused.
    const padded = try gpa.alloc(bool, lit_ntrees);
    defer gpa.free(padded);
    for (lit_counts, padded) |*h, *pad| {
        var any = false;
        for (h) |c| {
            if (c != 0) any = true;
        }
        pad.* = !any;
        if (!any) h[0] = 1;
    }

    // --- command codes: one per command block type ---------------------------
    const cmd_type_counts = try gpa.alloc(u32, it * tables.num_command_symbols);
    defer gpa.free(cmd_type_counts);
    if (it == 1) {
        @memcpy(cmd_type_counts, cmd_counts);
    } else {
        Matcher.fillZero(cmd_type_counts);
        var walk: TypeWalk = .{ .split = &blocks[1].split };
        for (res) |r| cmd_type_counts[@as(usize, walk.next()) * tables.num_command_symbols + r.sym] += 1;
    }
    for (0..it) |t| {
        const h = cmd_type_counts[t * tables.num_command_symbols ..][0..tables.num_command_symbols];
        if (std.mem.allEqual(u32, h, 0)) h[0] = 1;
    }

    // --- distance codes: per distance block type, its four contexts grouped
    // (`clusterDistances`); the groups of all types numbered in a row --------
    const dist_map = try gpa.alloc(u8, dt * dist_contexts);
    defer gpa.free(dist_map);
    const dist_type_counts = try gpa.alloc([dist_contexts][dist_alphabet_max]u32, dt);
    defer gpa.free(dist_type_counts);
    if (dt == 1) {
        for (&dist_type_counts[0], &dist_counts) |*o, *row| @memcpy(o[0..n_dist], row[0..n_dist]);
    } else {
        for (dist_type_counts) |*t| {
            for (t) |*row| @memset(row[0..n_dist], 0);
        }
        var walk: TypeWalk = .{ .split = &blocks[2].split };
        for (res) |r| {
            if (r.has_dist) dist_type_counts[walk.next()][r.dist_ctx][r.dist_sym] += 1;
        }
    }
    var dist_trees: usize = 0;
    const dist_tree_counts = try gpa.alloc([dist_alphabet_max]u32, dt * dist_contexts);
    defer gpa.free(dist_tree_counts);
    for (dist_tree_counts) |*row| @memset(row[0..n_dist], 0);
    for (0..dt) |t| {
        var m: [dist_contexts]u8 = undefined;
        const ntr = clusterDistances(&dist_type_counts[t], n_dist, &m);
        for (0..dist_contexts) |ctx| {
            dist_map[t * dist_contexts + ctx] = @intCast(dist_trees + m[ctx]);
            for (dist_type_counts[t][ctx][0..n_dist], dist_tree_counts[dist_trees + m[ctx]][0..n_dist]) |c, *o| o.* += c;
        }
        dist_trees += ntr;
    }
    // Every code needs at least one symbol even when unused.
    for (dist_tree_counts[0..dist_trees]) |*h| {
        if (std.mem.allEqual(u32, h[0..n_dist], 0)) h[0] = 1;
    }

    // --- meta-block header --------------------------------------------------
    try w.writeBits(@intFromBool(is_last), 1);
    if (is_last) try w.writeBits(0, 1); // ISLASTEMPTY = 0
    const mlen_minus_1: u32 = @intCast(n - 1);
    var size_nibbles: u6 = 4;
    if (mlen_minus_1 >= (1 << 20)) {
        size_nibbles = 6;
    } else if (mlen_minus_1 >= (1 << 16)) {
        size_nibbles = 5;
    }
    try w.writeBits(size_nibbles - 4, 2);
    try w.writeBits(mlen_minus_1, size_nibbles * 4);
    if (!is_last) try w.writeBits(0, 1); // ISUNCOMPRESSED = 0

    // NBLTYPES (and above one, the block type and count codes and the first
    // block's count) for literals, commands and distances.
    const lit_blocks_from = w.bitPos();
    try blocks[0].writeHeader(gpa, w);
    // The literal side's bits, to price one literal code against them.
    var lit_part = w.bitPos() - lit_blocks_from;
    try blocks[1].writeHeader(gpa, w);
    try blocks[2].writeHeader(gpa, w);
    try w.writeBits(env.dist.npostfix, 2);
    try w.writeBits(env.dist.ndirect >> env.dist.npostfix, 4);
    // A context mode per literal block type.
    for (lit_modes) |m| try w.writeBits(m, 2);
    lit_part += 2 * lt;
    // The literal and distance context maps.
    const map_from = w.bitPos();
    try writeContextMap(gpa, w, lit_map, lit_ntrees);
    lit_part += w.bitPos() - map_from;
    try writeContextMap(gpa, w, dist_map, dist_trees);

    const lit_codes = try gpa.alloc(Code, lit_ntrees);
    defer gpa.free(lit_codes);
    var built: usize = 0;
    defer for (lit_codes[0..built]) |*c| c.deinit(gpa);
    const codes_from = w.bitPos();
    while (built < lit_ntrees) : (built += 1) {
        lit_codes[built] = try buildAndWriteCodeRle(gpa, w, &lit_counts[built], tables.num_literal_symbols, tables.num_literal_symbols);
    }
    lit_part += w.bitPos() - codes_from;

    // With more than one literal code (or literal block type), price the
    // one-code alternative on exact bits: it differs from this block only
    // in the literal block types, context modes and map, the literal code
    // headers, the literal symbols and the literal block switches, all known
    // before a literal is written. `compressWith` writes it only when it is
    // no longer — rather than writing every such block twice.
    var single_no_worse = false;
    const multi_literal = lit_ntrees > 1 or lt > 1;
    if (multi_literal) {
        for (lit_counts, lit_codes, padded) |*h, *code, pad| {
            if (pad) continue;
            for (h, code.len) |c, l| lit_part += @as(usize, c) * l;
        }
        lit_part += blocks[0].switchBits();
        var scratch = BitWriter{ .gpa = gpa };
        defer scratch.buf.deinit(gpa);
        // NBLTYPES = 1, one context mode, a one-code map.
        try scratch.writeBits(0, 3);
        try writeContextMap(gpa, &scratch, &.{}, 1);
        // A block without literals still needs its one code (a one-symbol
        // simple code, `padded` for the others): without it the whole block
        // was refused and stored (found 2026-10-16, a 16 KiB tail of a
        // 17 MiB input, 19 → 16 387 bytes, once thirteen contexts were on).
        const no_lits = std.mem.allEqual(u32, &single_counts, 0);
        if (no_lits) single_counts[0] = 1;
        var single_code = try buildAndWriteCodeRle(gpa, &scratch, &single_counts, tables.num_literal_symbols, tables.num_literal_symbols);
        defer single_code.deinit(gpa);
        var single_part = scratch.bitPos();
        if (!no_lits) {
            for (single_counts, single_code.len) |c, l| single_part += @as(usize, c) * l;
        }
        single_no_worse = single_part <= lit_part;
    }
    const cmd_codes = try gpa.alloc(Code, it);
    defer gpa.free(cmd_codes);
    var cmd_built: usize = 0;
    defer for (cmd_codes[0..cmd_built]) |*c| c.deinit(gpa);
    while (cmd_built < it) : (cmd_built += 1) {
        cmd_codes[cmd_built] = try buildAndWriteCodeRle(gpa, w, cmd_type_counts[cmd_built * tables.num_command_symbols ..][0..tables.num_command_symbols], tables.num_command_symbols, tables.num_command_symbols);
    }
    const dist_codes = try gpa.alloc(Code, dist_trees);
    defer gpa.free(dist_codes);
    var dist_built: usize = 0;
    defer for (dist_codes[0..dist_built]) |*c| c.deinit(gpa);
    while (dist_built < dist_trees) : (dist_built += 1) {
        dist_codes[dist_built] = try buildAndWriteCodeRle(gpa, w, dist_tree_counts[dist_built][0..n_dist], n_dist, if (env.large_window) dist_alphabet_large_max else n_dist);
    }

    // --- commands -----------------------------------------------------------
    var lit_per_type = true;
    for (0..lt) |t| {
        const row = lit_map[t * num_contexts ..][0..num_contexts];
        if (!std.mem.allEqual(u8, row, row[0])) lit_per_type = false;
    }
    const layout: Layout = .{
        .lit_codes = lit_codes,
        .lit_map = lit_map,
        .lit_modes = lit_modes,
        .lit_per_type = lit_per_type,
        .cmd_codes = cmd_codes,
        .dist_codes = dist_codes,
        .dist_map = dist_map,
    };
    if (lt == 1 and it == 1 and dt == 1) {
        try emitCommands(false, w, input, start, cmds, res, &blocks, layout);
    } else {
        try emitCommands(true, w, input, start, cmds, res, &blocks, layout);
    }
    // Every block of every category was used up exactly.
    for (&blocks) |*b| {
        if (!b.done()) return error.EncoderInvariant;
    }
    return .{ .multi_literal = multi_literal, .single_no_worse = single_no_worse };
}

/// `.q0`/`.q1`'s meta-block of `n` bytes from its parse (`FragBlock`): one
/// block type and one code per category, no literal contexts. The size is
/// known from the histograms before any command is written: from
/// `budget_bits` (where storing the block would end) on, nothing more is
/// written (`error.NotSmaller`), so incompressible data costs no emission.
fn writeFragmentBlock(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    fb: *FragBlock,
    n: usize,
    is_last: bool,
    large_window: bool,
    budget_bits: usize,
) GiveUp!void {
    if (n == 0 or n > max_store_block) return error.EncoderInvariant;
    if (fb.recs.items.len == 0 or fb.covered != n) return error.EncoderInvariant;
    // Four histograms in turn: an increment does not wait on the one before
    // when two literals in a row are the same byte.
    var h4: [4][tables.num_literal_symbols]u32 = @splat(@splat(0));
    const lits = fb.lits.items;
    {
        var k: usize = 0;
        while (k + 4 <= lits.len) : (k += 4) {
            inline for (0..4) |j| h4[j][lits[k + j]] += 1;
        }
        while (k < lits.len) : (k += 1) h4[0][lits[k]] += 1;
    }
    var lit_counts: [tables.num_literal_symbols]u32 = undefined;
    for (&lit_counts, h4[0], h4[1], h4[2], h4[3]) |*o, a, b, c, d| o.* = a + b + c + d;
    if (lits.len == 0) lit_counts[0] = 1;
    const n_dist: u32 = if (large_window) dist_alphabet_large else dist_alphabet_size;
    const dist_counts = fb.dist_counts1[1..][0..n_dist];
    if (std.mem.allEqual(u32, dist_counts, 0)) dist_counts[0] = 1;

    // --- meta-block header --------------------------------------------------
    try w.writeBits(@intFromBool(is_last), 1);
    if (is_last) try w.writeBits(0, 1); // ISLASTEMPTY = 0
    const mlen_minus_1: u32 = @intCast(n - 1);
    const size_nibbles: u6 = if (mlen_minus_1 >= (1 << 20)) 6 else if (mlen_minus_1 >= (1 << 16)) 5 else 4;
    try w.writeBits(size_nibbles - 4, 2);
    try w.writeBits(mlen_minus_1, size_nibbles * 4);
    if (!is_last) try w.writeBits(0, 1); // ISUNCOMPRESSED = 0
    // NBLTYPES 1 for all three, NPOSTFIX = NDIRECT = 0, context mode LSB6,
    // NTREESL 1, NTREESD 1: thirteen zero bits.
    try w.writeBits(0, 13);
    var lit_code = try buildAndWriteCode(gpa, w, &lit_counts, tables.num_literal_symbols);
    defer lit_code.deinit(gpa);
    var cmd_code = try buildAndWriteCode(gpa, w, &fb.cmd_counts, tables.num_command_symbols);
    defer cmd_code.deinit(gpa);
    var dist_code = try buildAndWriteCodeWide(gpa, w, dist_counts, n_dist, if (large_window) dist_alphabet_large_max else dist_alphabet_size);
    defer dist_code.deinit(gpa);

    var payload: usize = 0;
    for (fb.recs.items) |r| payload += @intCast(r.extraN() + r.distN());
    for (lit_counts, lit_code.len) |k, l| payload += @as(usize, k) * l;
    for (fb.cmd_counts, cmd_code.len) |k, l| payload += @as(usize, k) * l;
    for (dist_counts, dist_code.len) |k, l| payload += @as(usize, k) * l;
    if (w.bitPos() + payload >= budget_bits) return error.NotSmaller;

    // --- commands, into room reserved for exactly them ----------------------
    // No capacity check per write: whole bytes go out eight at a time (an
    // unaligned store; the reserve keeps the slack), at most seven bits stay
    // pending, so up to 57 bits are added between flushes. Plain locals, not
    // a struct behind a pointer: a store through `ptr` may alias anything
    // in memory, and such a struct's fields were reloaded after every one
    // (a third of `.q0`'s cycles on html, 2026-10-15).
    try w.room((w.cnt + payload) / 8 + 16);
    const base = w.buf.items.ptr + w.buf.items.len;
    var ptr = base;
    var acc: u64 = w.acc;
    var cnt: u64 = w.cnt;
    const flush = struct {
        // `k` < 64: the shift is the bits of the bytes that went out.
        inline fn f(pp: *[*]u8, a: *u64, k: *u64) void {
            std.mem.writeInt(u64, pp.*[0..8], a.*, .little);
            pp.* += @intCast(k.* >> 3);
            a.* >>= @as(u6, @truncate(k.* & 56));
            k.* &= 7;
        }
    }.f;
    flush(&ptr, &acc, &cnt); // `w` holds up to 31 pending bits
    const lbits = lit_code.bits;
    const llen = lit_code.len;
    const cbits = cmd_code.bits;
    const clen = cmd_code.len;
    // The distance code from "none" on (`FragRec.distSym1`): a command
    // without a distance writes zero bits, no branch.
    var dbits1: [dist_alphabet_large + 1]u16 = undefined;
    var dlen1: [dist_alphabet_large + 1]u8 = undefined;
    dbits1[0] = 0;
    dlen1[0] = 0;
    @memcpy(dbits1[1..][0..n_dist], dist_code.bits);
    @memcpy(dlen1[1..][0..n_dist], dist_code.len);
    const padded = fb.lits.allocatedSlice();
    var lp: usize = 0;
    for (fb.recs.items) |r| {
        const sym = r.sym();
        const cl: u64 = clen[sym];
        const en = r.extraN();
        if (cl + en <= 56) {
            acc |= (cbits[sym] | (r.cmd >> 16) << @intCast(cl)) << @intCast(cnt);
            cnt += cl + en;
        } else {
            // Long insert and copy at once (up to 63 bits): in two.
            acc |= @as(u64, cbits[sym]) << @intCast(cnt);
            cnt += cl;
            flush(&ptr, &acc, &cnt);
            acc |= (r.cmd >> 16) << @intCast(cnt);
            cnt += en;
        }
        flush(&ptr, &acc, &cnt);
        // Literals three at a time (45 bits), the last group masked: one
        // round for the short inserts most commands have.
        const insert = r.insertLen();
        var k: usize = 0;
        while (k < insert) : (k += 3) {
            inline for (0..3) |j| {
                const on: u64 = @intFromBool(k + j < insert);
                const b = padded[lp + k + j];
                acc |= (@as(u64, lbits[b]) & (0 -% on)) << @intCast(cnt);
                cnt += llen[b] * on;
            }
            flush(&ptr, &acc, &cnt);
        }
        lp += insert;
        const d1 = r.distSym1();
        const dl: u64 = dlen1[d1];
        acc |= (dbits1[d1] | (r.dst >> 34) << @intCast(dl)) << @intCast(cnt);
        cnt += dl + r.distN();
        flush(&ptr, &acc, &cnt);
    }
    w.buf.items.len += @intCast(ptr - base);
    w.acc = acc;
    w.cnt = @intCast(cnt);
}

/// Block-split parameters per category: about how many symbols a starting
/// histogram covers, the sampled window, and what a block switch is priced.
fn lit_split_params(rounds: u32) block_split.Params {
    return .{ .per_histogram = 544, .sample = 70, .switch_cost = 28, .rounds = rounds, .histograms = 32 };
}

fn cmd_split_params(rounds: u32) block_split.Params {
    return .{ .per_histogram = 530, .sample = 40, .switch_cost = 13.5, .rounds = rounds, .histograms = 32 };
}

fn dist_split_params(rounds: u32) block_split.Params {
    return .{ .per_histogram = 544, .sample = 40, .switch_cost = 14.5, .rounds = rounds, .histograms = 32 };
}

/// The block type of each symbol in turn, along a split.
const TypeWalk = struct {
    split: *const block_split.Split,
    b: usize = 0,
    left: u32 = 0,
    started: bool = false,

    fn next(w: *TypeWalk) u8 {
        if (!w.started) {
            w.started = true;
            w.left = w.split.lens[0];
        }
        while (w.left == 0) {
            w.b += 1;
            w.left = w.split.lens[w.b];
        }
        w.left -= 1;
        return w.split.types[w.b];
    }
};

// ---------------------------------------------------------------------------
// `.q0` (2026-10-16): google/brotli's quality 0, ported from
// `c/enc/compress_fragment.c` (`BrotliCompressFragmentFast`) and the default
// command code of `c/enc/encode.c` (`InitCommandPrefixCodes`) — MIT,
// copyright Google Inc., see this module's NOTICE. One pass: the literal
// code is built from a meta-block's bytes before any match is looked for,
// the command and distance codes are the previous meta-block's (google's
// defaults for the first), and a match goes out the moment it is found, as
// two commands — "insert N, copy 2" with its distance, then "insert 0, copy
// the rest" at the last distance — whose symbols the codes keep in an order
// that saves branches (`Q0Codes`). No record, no second pass: the parse
// and writer of `.q1` cost twice the instructions a command (2026-10-15).
// Changes: one call per `Core` block (google: per input chunk), the hash
// table is `FragMatcher`'s, bits go through `Q0Bits` (locals, a
// branch-free flush), a block larger than stored is stored by
// `compressBlock` as at every level, and the meta-blocks are never ISLAST
// (`Core.finish` adds the empty last one, as google's adds its own).

/// Matches reach this far at most (google `MAX_DISTANCE`, an 18-bit window).
const q0_max_distance = (1 << 18) - 16;
const q0_min_match = 5;
/// Bytes at the end of the input no match starts in: the hash loads eight
/// (google `kInputMarginBytes`).
const q0_input_margin = 16;
/// A meta-block starts with this many bytes and grows by `q0_merge_block`
/// while the next bytes suit its literal code, to 1 MiB.
const q0_first_block = 3 << 15;
const q0_merge_block = 1 << 16;
/// Room for a pre-written command and distance code (`Q0Codes.code`).
const q0_code_max = 1024;

/// `kCmdHistoSeed`: where a meta-block's command and distance counts start.
const q0_cmd_histo_seed = [128]u32{
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 0, 0, 0, 0,
};

/// `.q0`'s command and distance codes. Entries 0..63 are the 64 command
/// symbols it writes in its own order (`q0InsertLen` and the others index
/// them; `q0StoreCommandCodes` has the map to the alphabet), 64..127 the
/// distance symbols 0..63.
const Q0Codes = struct {
    depth: [128]u8,
    bits: [128]u16,
    /// Both codes as the stream carries them, for the next block's first
    /// meta-block.
    code: [q0_code_max]u8,
    code_bits: usize,

    const default: Q0Codes = .{
        // (google's arrays end four short: zeros.)
        .depth = [_]u8{
            0,  4,  4,  5,  6,  6,  7,  7,  7,  7,  7,  8,  8,  8,  8,  8,
            0,  0,  0,  4,  4,  4,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,
            7,  7,  10, 10, 10, 10, 10, 10, 0,  4,  4,  5,  5,  5,  6,  6,
            7,  8,  8,  9,  10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
            5,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
            6,  6,  6,  6,  6,  6,  5,  5,  5,  5,  5,  5,  4,  4,  4,  4,
            4,  4,  4,  5,  5,  5,  5,  5,  5,  6,  6,  7,  7,  7,  8,  10,
            12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
        } ++ [_]u8{0} ** 4,
        .bits = [_]u16{
            0,    0,    8,    9,    3,   35,   7,    71,
            39,   103,  23,   47,   175, 111,  239,  31,
            0,    0,    0,    4,    12,  2,    10,   6,
            13,   29,   11,   43,   27,  59,   87,   55,
            15,   79,   319,  831,  191, 703,  447,  959,
            0,    14,   1,    25,   5,   21,   19,   51,
            119,  159,  95,   223,  479, 991,  63,   575,
            127,  639,  383,  895,  255, 767,  511,  1023,
            14,   0,    0,    0,    0,   0,    0,    0,
            0,    0,    0,    0,    0,   0,    0,    0,
            27,   59,   7,    39,   23,  55,   30,   1,
            17,   9,    25,   5,    0,   8,    4,    12,
            2,    10,   6,    21,   13,  29,   3,    19,
            11,   15,   47,   31,   95,  63,   127,  255,
            767,  2815, 1791, 3839, 511, 2559, 1535, 3583,
            1023, 3071, 2047, 4095,
        } ++ [_]u16{0} ** 4,
        .code = [_]u8{
            0xff, 0x77, 0xd5, 0xbf, 0xe7, 0xde, 0xea, 0x9e, 0x51, 0x5d, 0xde, 0xc6,
            0x70, 0x57, 0xbc, 0x58, 0x58, 0x58, 0xd8, 0xd8, 0x58, 0xd5, 0xcb, 0x8c,
            0xea, 0xe0, 0xc3, 0x87, 0x1f, 0x83, 0xc1, 0x60, 0x1c, 0x67, 0xb2, 0xaa,
            0x06, 0x83, 0xc1, 0x60, 0x30, 0x18, 0xcc, 0xa1, 0xce, 0x88, 0x54, 0x94,
            0x46, 0xe1, 0xb0, 0xd0, 0x4e, 0xb2, 0xf7, 0x04, 0x00,
        } ++ [_]u8{0} ** (q0_code_max - 57),
        .code_bits = 448,
    };
};

/// Bits straight into a `BitWriter`'s reserved room: the pending bits in
/// locals, eight bytes stored after every write and the whole bytes
/// counted (at most seven bits stay pending).
const Q0Bits = struct {
    base: [*]u8,
    ptr: [*]u8,
    acc: u64,
    cnt: u32,

    /// Continue `w` (its pending bits too); room must be reserved, eight
    /// bytes past the last one written.
    fn open(w: *const BitWriter) Q0Bits {
        const base = w.buf.items.ptr + w.buf.items.len;
        var b: Q0Bits = .{ .base = base, .ptr = base, .acc = 0, .cnt = 0 };
        b.put(w.cnt, w.acc);
        return b;
    }

    fn close(b: *const Q0Bits, w: *BitWriter) void {
        w.buf.items.len += @intFromPtr(b.ptr) - @intFromPtr(b.base);
        w.acc = b.acc;
        w.cnt = @intCast(b.cnt);
    }

    /// `n` bits (at most 56) of `v`, which has none above them.
    inline fn put(b: *Q0Bits, n: u32, v: u64) void {
        b.acc |= v << @intCast(b.cnt);
        b.cnt += n;
        std.mem.writeInt(u64, b.ptr[0..8], b.acc, .little);
        b.ptr += b.cnt >> 3;
        b.acc >>= @intCast(b.cnt & 56);
        b.cnt &= 7;
    }

    inline fn sym(b: *Q0Bits, c: *const Q0Codes, h: *[128]u32, code: usize) void {
        b.put(c.depth[code], c.bits[code]);
        h[code] += 1;
    }
};

inline fn log2Floor(x: usize) u32 {
    return std.math.log2_int(usize, x);
}

/// google `EmitInsertLen`: insert < 6210, with copy 2.
inline fn q0InsertLen(b: *Q0Bits, c: *const Q0Codes, h: *[128]u32, insert: usize) void {
    if (insert < 6) {
        b.sym(c, h, insert + 40);
    } else if (insert < 130) {
        const tail = insert - 2;
        const nbits = log2Floor(tail) - 1;
        const prefix = tail >> @intCast(nbits);
        b.sym(c, h, (nbits << 1) + prefix + 42);
        b.put(nbits, tail - (prefix << @intCast(nbits)));
    } else if (insert < 2114) {
        const tail = insert - 66;
        const nbits = log2Floor(tail);
        b.sym(c, h, nbits + 50);
        b.put(nbits, tail - (@as(usize, 1) << @intCast(nbits)));
    } else {
        b.sym(c, h, 61);
        b.put(12, insert - 2114);
    }
}

/// google `EmitLongInsertLen`.
inline fn q0LongInsertLen(b: *Q0Bits, c: *const Q0Codes, h: *[128]u32, insert: usize) void {
    if (insert < 22594) {
        b.sym(c, h, 62);
        b.put(14, insert - 6210);
    } else {
        b.sym(c, h, 63);
        b.put(24, insert - 22594);
    }
}

/// google `EmitCopyLen`: insert 0, the distance written after.
inline fn q0CopyLen(b: *Q0Bits, c: *const Q0Codes, h: *[128]u32, copy: usize) void {
    if (copy < 10) {
        b.sym(c, h, copy + 14);
    } else if (copy < 134) {
        const tail = copy - 6;
        const nbits = log2Floor(tail) - 1;
        const prefix = tail >> @intCast(nbits);
        b.sym(c, h, (nbits << 1) + prefix + 20);
        b.put(nbits, tail - (prefix << @intCast(nbits)));
    } else if (copy < 2118) {
        const tail = copy - 70;
        const nbits = log2Floor(tail);
        b.sym(c, h, nbits + 28);
        b.put(nbits, tail - (@as(usize, 1) << @intCast(nbits)));
    } else {
        b.sym(c, h, 39);
        b.put(24, copy - 2118);
    }
}

/// google `EmitCopyLenLastDistance`: insert 0 at the last distance (the
/// implicit symbols up to 71 bytes, then the code's "last distance").
inline fn q0CopyLenLastDistance(b: *Q0Bits, c: *const Q0Codes, h: *[128]u32, copy: usize) void {
    if (copy < 12) {
        b.sym(c, h, copy - 4);
    } else if (copy < 72) {
        const tail = copy - 8;
        const nbits = log2Floor(tail) - 1;
        const prefix = tail >> @intCast(nbits);
        b.sym(c, h, (nbits << 1) + prefix + 4);
        b.put(nbits, tail - (prefix << @intCast(nbits)));
    } else if (copy < 136) {
        const tail = copy - 8;
        b.sym(c, h, (tail >> 5) + 30);
        b.put(5, tail & 31);
        b.sym(c, h, 64);
    } else if (copy < 2120) {
        const tail = copy - 72;
        const nbits = log2Floor(tail);
        b.sym(c, h, nbits + 28);
        b.put(nbits, tail - (@as(usize, 1) << @intCast(nbits)));
        b.sym(c, h, 64);
    } else {
        b.sym(c, h, 39);
        b.put(24, copy - 2120);
        b.sym(c, h, 64);
    }
}

/// google `EmitDistance`: distance codes 16 and up (NPOSTFIX = NDIRECT = 0).
inline fn q0Distance(b: *Q0Bits, c: *const Q0Codes, h: *[128]u32, distance: usize) void {
    const d = distance + 3;
    const nbits = log2Floor(d) - 1;
    const prefix = (d >> @intCast(nbits)) & 1;
    const offset = (2 + prefix) << @intCast(nbits);
    b.sym(c, h, 2 * (nbits - 1) + prefix + 80);
    b.put(nbits, d - offset);
}

inline fn q0Literals(b: *Q0Bits, lit: *const Code, bytes: []const u8) void {
    for (bytes) |x| b.put(lit.len[x], lit.bits[x]);
}

/// google `BuildAndStoreLiteralPrefixCode`: a code of at most 14 bits
/// (`BrotliBuildAndStoreHuffmanTreeFast`; its `max_bits`, 8, is a simple
/// code's symbol width) from the bytes before the parse (all of them under 32 KiB, every 29th
/// above, then each symbol's first 11 counted three times — the parse
/// takes the frequent ones into copies); also the estimated ratio, in
/// thousandths of a byte per byte.
fn q0LiteralCode(gpa: std.mem.Allocator, w: *BitWriter, bytes: []const u8, ratio: *usize) GiveUp!Code {
    var h: [tables.num_literal_symbols]u32 = @splat(0);
    var total: usize = 0;
    if (bytes.len < (1 << 15)) {
        for (bytes) |x| h[x] += 1;
        total = bytes.len;
        for (&h) |*v| {
            const first: u32 = @min(v.*, 11); // (`@min` narrows to u4)
            const adjust = 2 * first;
            v.* += adjust;
            total += adjust;
        }
    } else {
        const rate = 29;
        var i: usize = 0;
        while (i < bytes.len) : (i += rate) h[bytes[i]] += 1;
        total = (bytes.len + rate - 1) / rate;
        for (&h) |*v| {
            const first: u32 = @min(v.*, 11);
            const adjust = 1 + 2 * first;
            v.* += adjust;
            total += adjust;
        }
    }
    const code = try buildAndWriteCodeLimited(gpa, w, &h, tables.num_literal_symbols, tables.num_literal_symbols, 14);
    var bits: usize = 0;
    for (h, code.len) |k, l| bits += @as(usize, k) * l;
    ratio.* = bits * 125 / total;
    return code;
}

/// google `BuildAndStoreCommandPrefixCode`: the command and distance codes
/// for counts `h` into `c` and onto `w`. The command code is built over the
/// 64 symbols in `.q0`'s order and written over the alphabet; its canonical
/// bits are computed in the alphabet's order (`tmp`), which is `.q0`'s
/// order but for entry 40 — insert 0 with copy 2, the alphabet's 128, which
/// `.q0` never writes (a match costs an insert of at least one).
fn q0StoreCommandCodes(gpa: std.mem.Allocator, w: *BitWriter, h: *const [128]u32, c: *Q0Codes) GiveUp!void {
    var depth: [128]u8 = undefined;
    _ = try assignLengths(gpa, h[0..64], 15, depth[0..64]);
    _ = try assignLengths(gpa, h[64..128], 14, depth[64..128]);
    if (depth[40] != 0 or depth[16] != 0) return error.EncoderInvariant;
    var tmp: [64]u8 = undefined;
    @memcpy(tmp[0..24], depth[0..24]);
    @memcpy(tmp[24..32], depth[40..48]);
    @memcpy(tmp[32..40], depth[24..32]);
    @memcpy(tmp[40..48], depth[48..56]);
    @memcpy(tmp[48..56], depth[32..40]);
    @memcpy(tmp[56..64], depth[56..64]);
    var tcode = try canonicalCode(gpa, &tmp);
    defer tcode.deinit(gpa);
    var bits: [128]u16 = undefined;
    @memcpy(bits[0..24], tcode.bits[0..24]);
    @memcpy(bits[24..32], tcode.bits[32..40]);
    @memcpy(bits[32..40], tcode.bits[48..56]);
    @memcpy(bits[40..48], tcode.bits[24..32]);
    @memcpy(bits[48..56], tcode.bits[40..48]);
    @memcpy(bits[56..64], tcode.bits[56..64]);
    var dcode = try canonicalCode(gpa, depth[64..128]);
    defer dcode.deinit(gpa);
    @memcpy(bits[64..128], dcode.bits);

    var full: [tables.num_command_symbols]u8 = @splat(0);
    @memcpy(full[0..8], depth[0..8]);
    @memcpy(full[64..72], depth[8..16]);
    @memcpy(full[128..136], depth[16..24]);
    @memcpy(full[192..200], depth[24..32]);
    @memcpy(full[384..392], depth[32..40]);
    for (0..8) |i| {
        full[128 + 8 * i] = depth[40 + i];
        full[256 + 8 * i] = depth[48 + i];
        full[448 + 8 * i] = depth[56 + i];
    }
    try writeComplexCode(gpa, w, &full);
    try writeComplexCode(gpa, w, depth[64..128]);
    c.depth = depth;
    c.bits = bits;
}

/// `q0StoreCommandCodes` into `c.code`, for the next block's first
/// meta-block (google: `s->cmd_code`).
fn q0PrepareCommandCodes(gpa: std.mem.Allocator, h: *const [128]u32, c: *Q0Codes) GiveUp!void {
    var tw: BitWriter = .{ .gpa = gpa };
    defer tw.buf.deinit(gpa);
    try q0StoreCommandCodes(gpa, &tw, h, c);
    const whole = tw.buf.items.len;
    const pending = (@as(usize, tw.cnt) + 7) / 8;
    if (whole + pending > q0_code_max) return error.EncoderInvariant;
    @memcpy(c.code[0..whole], tw.buf.items);
    for (0..pending) |k| c.code[whole + k] = @truncate(tw.acc >> @intCast(8 * k));
    c.code_bits = tw.bitPos();
}

fn q0WriteCommandCodes(w: *BitWriter, c: *const Q0Codes) std.mem.Allocator.Error!void {
    var i: usize = 0;
    while (i + 8 <= c.code_bits) : (i += 8) try w.writeBits(c.code[i / 8], 8);
    const rest: u6 = @intCast(c.code_bits & 7);
    if (rest != 0) try w.writeBits(c.code[i / 8] & ((@as(u8, 1) << @intCast(rest)) - 1), rest);
}

/// A compressed meta-block's header, not ISLAST, then NBLTYPES 1 for all
/// three, NPOSTFIX = NDIRECT = 0, context mode, NTREESL and NTREESD 1.
fn q0Header(w: *BitWriter, len: usize) std.mem.Allocator.Error!void {
    const nibbles: u6 = if (len <= 1 << 16) 4 else if (len <= 1 << 20) 5 else 6;
    try w.writeBits(0, 1);
    try w.writeBits(nibbles - 4, 2);
    try w.writeBits(@intCast(len - 1), nibbles * 4);
    try w.writeBits(0, 1);
    try w.writeBits(0, 13);
}

/// google `UpdateBits`: `n` bits of `v` over what is at bit `pos` (written
/// out already).
fn q0UpdateBits(w: *BitWriter, n_in: u32, v_in: u32, pos_in: usize) void {
    var n = n_in;
    var v = v_in;
    var pos = pos_in;
    const array = w.buf.items;
    while (n > 0) {
        const byte_pos = pos >> 3;
        const unchanged: u5 = @intCast(pos & 7);
        const changed: u5 = @intCast(@min(n, 8 - @as(u32, unchanged)));
        const total: u5 = unchanged + changed;
        const mask: u32 = ~((@as(u32, 1) << total) - 1) | ((@as(u32, 1) << unchanged) - 1);
        const keep = array[byte_pos] & mask;
        const new = v & ((@as(u32, 1) << changed) - 1);
        array[byte_pos] = @truncate((new << unchanged) | keep);
        n -= changed;
        v >>= changed;
        pos += changed;
    }
}

/// google `ShouldMergeBlock`: whether the next bytes suit the literal code
/// (`depth`) well enough to continue the meta-block.
fn q0ShouldMerge(bytes: []const u8, depth: []const u8) bool {
    const rate = 43;
    var h: [tables.num_literal_symbols]u32 = @splat(0);
    var i: usize = 0;
    while (i < bytes.len) : (i += rate) h[bytes[i]] += 1;
    const total = (bytes.len + rate - 1) / rate;
    const t: f64 = @floatFromInt(total);
    var r: f64 = (greedy_split.fastLog2(total) + 0.5) * t + 200;
    for (h, depth) |k, d| {
        if (k == 0) continue;
        r -= @as(f64, @floatFromInt(k)) * (@as(f64, @floatFromInt(d)) + greedy_split.fastLog2(k));
    }
    return r >= 0;
}

inline fn q0Hash(in: []const u8, p: usize, shift: u6) u32 {
    const v = std.mem.readInt(u64, in[p..][0..8], .little);
    return @truncate(((v << 24) *% 0x1e35a7bd) >> shift);
}

inline fn q0HashAt(v: u64, comptime offset: u6, shift: u6) u32 {
    return @truncate((((v >> (8 * offset)) << 24) *% 0x1e35a7bd) >> shift);
}

inline fn q0IsMatch(in: []const u8, p1: usize, p2: usize) bool {
    return std.mem.readInt(u32, in[p1..][0..4], .little) == std.mem.readInt(u32, in[p2..][0..4], .little) and in[p1 + 4] == in[p2 + 4];
}

/// The positions inside a copy that ends at `ip` go into the table, and the
/// candidate for `ip` comes out of it.
inline fn q0AfterCopy(in: []const u8, table: []u32, ip: usize, shift: u6) usize {
    const v = std.mem.readInt(u64, in[ip - 3 ..][0..8], .little);
    const cur = q0HashAt(v, 3, shift);
    table[q0HashAt(v, 0, shift)] = @intCast(ip - 3);
    table[q0HashAt(v, 1, shift)] = @intCast(ip - 2);
    table[q0HashAt(v, 2, shift)] = @intCast(ip - 1);
    const candidate: usize = table[cur];
    table[cur] = @intCast(ip);
    return candidate;
}

const Q0Block = struct {
    in: []const u8,
    table: []u32,
    shift: u6,
    max_distance: usize,
    codes: *Q0Codes,
    histo: *[128]u32,
    lit: *const Code,
    literal_ratio: usize,
    metablock_start: usize,
    input_size: usize,
};

/// google's `emit_commands`: the commands of `in[input..][0..block_size]`,
/// from `next_emit.*` on. Null when the rest goes out as an insert; else
/// where the meta-block so far is to be stored instead.
fn q0Commands(b: *Q0Bits, x: *const Q0Block, input: usize, block_size: usize, next_emit: *usize) ?usize {
    const in = x.in;
    const table = x.table;
    const shift = x.shift;
    const c = x.codes;
    const h = x.histo;
    if (block_size < q0_input_margin) return null;
    const ip_end = input + block_size;
    const len_limit = @min(block_size - q0_min_match, x.input_size - q0_input_margin);
    const ip_limit = input + len_limit;
    var last_distance: usize = 0; // none
    var ip = input + 1;
    var next_hash = q0Hash(in, ip, shift);
    while (true) {
        // Step 1: a 5-byte match, looking at every byte, one byte further
        // apart every 32 misses (Snappy's skipping).
        var skip: u32 = 32;
        var next_ip = ip;
        var candidate: usize = undefined;
        while (true) {
            while (true) {
                const hash = next_hash;
                const step = skip >> 5;
                skip += 1;
                ip = next_ip;
                next_ip = ip + step;
                if (next_ip > ip_limit) return null;
                next_hash = q0Hash(in, next_ip, shift);
                if (last_distance != 0 and q0IsMatch(in, ip, ip - last_distance)) {
                    candidate = ip - last_distance;
                    table[hash] = @intCast(ip);
                    break;
                }
                candidate = table[hash];
                table[hash] = @intCast(ip);
                if (q0IsMatch(in, ip, candidate)) break;
            }
            if (ip - candidate <= x.max_distance) break;
        }

        // Step 2: the match and the literals before it.
        {
            const base = ip;
            const matched = q0_min_match + Matcher.matchLen(in, candidate + q0_min_match, ip + q0_min_match, ip_end - ip - q0_min_match);
            const distance = base - candidate;
            const insert = base - next_emit.*;
            ip += matched;
            if (insert < 6210) {
                q0InsertLen(b, c, h, insert);
            } else if (next_emit.* - x.metablock_start <= insert / 50 and x.literal_ratio > 980) {
                // google `ShouldUseUncompressedMode`: barely compressed so far
                // and a long insert of poorly coded literals.
                return base;
            } else {
                q0LongInsertLen(b, c, h, insert);
            }
            q0Literals(b, x.lit, in[next_emit.*..base]);
            if (distance == last_distance) {
                b.sym(c, h, 64);
            } else {
                q0Distance(b, c, h, distance);
                last_distance = distance;
            }
            q0CopyLenLastDistance(b, c, h, matched);
            next_emit.* = ip;
            if (ip >= ip_limit) return null;
            candidate = q0AfterCopy(in, table, ip, shift);
        }
        // Further matches right after, with no literals between.
        while (q0IsMatch(in, ip, candidate)) {
            const base = ip;
            const matched = q0_min_match + Matcher.matchLen(in, candidate + q0_min_match, ip + q0_min_match, ip_end - ip - q0_min_match);
            if (ip - candidate > x.max_distance) break;
            ip += matched;
            last_distance = base - candidate;
            q0CopyLen(b, c, h, matched);
            q0Distance(b, c, h, last_distance);
            next_emit.* = ip;
            if (ip >= ip_limit) return null;
            candidate = q0AfterCopy(in, table, ip, shift);
        }
        ip += 1;
        next_hash = q0Hash(in, ip, shift);
    }
}

/// `.q0`'s meta-blocks for `in` (google `BrotliCompressFragmentFastImpl`)
/// with `table` (`FragMatcher`'s), starting from the codes in `codes`,
/// which it updates as google's does; `histo` is left with the last
/// meta-block's command and distance counts (`q0PrepareCommandCodes`).
fn writeQ0(gpa: std.mem.Allocator, w: *BitWriter, in: []const u8, table_all: []u32, max_distance: usize, codes: *Q0Codes, histo: *[128]u32) GiveUp!void {
    if (in.len == 0) return error.EncoderInvariant;
    // google `HashTableSize` for quality 0: the input's size from 2^8 to
    // 2^15, an odd power of two.
    var ht: usize = 256;
    while (ht < (1 << 15) and ht < in.len) ht <<= 1;
    if (ht & 0xAAAAA == 0) ht <<= 1;
    ht = @min(ht, table_all.len);
    const table = table_all[0..ht];
    Matcher.fillZero(table);

    var x: Q0Block = .{
        .in = in,
        .table = table,
        .shift = @intCast(64 - log2Floor(ht)),
        .max_distance = @min(max_distance, q0_max_distance),
        .codes = codes,
        .histo = histo,
        .lit = undefined,
        .literal_ratio = 0,
        .metablock_start = 0,
        .input_size = in.len,
    };
    var input: usize = 0;
    var next_emit: usize = 0;
    var block_size: usize = @min(in.len, q0_first_block);
    var total_block_size: usize = block_size;
    var header = w.mark();
    var mlen_pos = w.bitPos() + 3;
    try q0Header(w, block_size);
    var lit = try q0LiteralCode(gpa, w, in[0..block_size], &x.literal_ratio);
    defer lit.deinit(gpa);
    x.lit = &lit;
    try q0WriteCommandCodes(w, codes);

    while (true) {
        histo.* = q0_cmd_histo_seed;
        // At most 16 bits a byte (google reserves the same).
        try w.room(2 * block_size + 64);
        var b = Q0Bits.open(w);
        if (q0Commands(&b, &x, input, block_size, &next_emit)) |base| {
            b.close(w);
            w.rollback(header);
            try writeStoreBlock(w, in[x.metablock_start..base]);
            x.input_size -= base - input;
            input = base;
            next_emit = input;
        } else {
            const ip_end = input + block_size;
            input += block_size;
            x.input_size -= block_size;
            block_size = @min(x.input_size, q0_merge_block);
            // Continue the meta-block while the next bytes suit its
            // literal code: its MLEN has five nibbles from the start.
            if (x.input_size > 0 and total_block_size + block_size <= 1 << 20 and q0ShouldMerge(in[input..][0..block_size], lit.len)) {
                b.close(w);
                total_block_size += block_size;
                q0UpdateBits(w, 20, @intCast(total_block_size - 1), mlen_pos);
                continue;
            }
            var stored = false;
            if (next_emit < ip_end) {
                const insert = ip_end - next_emit;
                if (insert < 6210) {
                    q0InsertLen(&b, codes, histo, insert);
                    q0Literals(&b, &lit, in[next_emit..ip_end]);
                } else if (next_emit - x.metablock_start <= insert / 50 and x.literal_ratio > 980) {
                    b.close(w);
                    w.rollback(header);
                    try writeStoreBlock(w, in[x.metablock_start..ip_end]);
                    stored = true;
                } else {
                    q0LongInsertLen(&b, codes, histo, insert);
                    q0Literals(&b, &lit, in[next_emit..ip_end]);
                }
            }
            next_emit = ip_end;
            if (!stored) b.close(w);
        }
        if (x.input_size == 0) return;
        // The next meta-block, with codes from this one's counts.
        x.metablock_start = input;
        block_size = @min(x.input_size, q0_first_block);
        total_block_size = block_size;
        header = w.mark();
        mlen_pos = w.bitPos() + 3;
        try q0Header(w, block_size);
        const next_lit = try q0LiteralCode(gpa, w, in[input..][0..block_size], &x.literal_ratio);
        lit.deinit(gpa);
        lit = next_lit;
        try q0StoreCommandCodes(gpa, w, histo, codes);
    }
}

/// RFC 7932 §6: the block count code for a block of `len` symbols.
fn blockLenCode(len: u32) struct { code: u5, extra: u32, nbits: u5 } {
    var c: usize = tables.num_block_len_symbols - 1;
    while (tables.block_length_ranges[c].offset > len) c -= 1;
    const r = tables.block_length_ranges[c];
    return .{ .code = @intCast(c), .extra = len - r.offset, .nbits = @intCast(r.nbits) };
}

/// One category's blocks as written: the header part (NBLTYPES, the block
/// type and count codes, the first count) and, before each symbol, a block
/// switch when the block before ran out — as the decoder counts them.
const BlockCodes = struct {
    split: block_split.Split,
    /// Each block's type code (RFC 7932 §6: 0 = the type before the last,
    /// 1 = the last + 1, else type + 2); the first block's is unused (type 0).
    tcode: []u16,
    type_code: ?Code = null,
    len_code: ?Code = null,
    b: usize = 0,
    left: u32 = 0,

    fn init(gpa: std.mem.Allocator, split: block_split.Split) std.mem.Allocator.Error!BlockCodes {
        var s = split;
        errdefer s.deinit(gpa);
        const tcode = try gpa.alloc(u16, s.types.len);
        // The decoder's ring of the last two types starts {1, 0}.
        var second: u32 = 1;
        var last: u32 = 0;
        tcode[0] = 0;
        for (s.types[1..], tcode[1..]) |t, *code| {
            code.* = if (t == (last + 1) % s.ntypes) 1 else if (t == second) 0 else @as(u16, t) + 2;
            second = last;
            last = t;
        }
        return .{ .split = s, .tcode = tcode, .left = s.lens[0] };
    }

    fn deinit(bc: *BlockCodes, gpa: std.mem.Allocator) void {
        if (bc.type_code) |*c| c.deinit(gpa);
        if (bc.len_code) |*c| c.deinit(gpa);
        gpa.free(bc.tcode);
        bc.split.deinit(gpa);
        bc.* = undefined;
    }

    fn writeHeader(bc: *BlockCodes, gpa: std.mem.Allocator, w: *BitWriter) GiveUp!void {
        const nt = bc.split.ntypes;
        try writeVarLenUint8(w, @intCast(nt - 1));
        if (nt == 1) return;
        var tc: [256 + 2]u32 = @splat(0);
        var lc: [tables.num_block_len_symbols]u32 = @splat(0);
        for (bc.tcode[1..]) |c| tc[c] += 1;
        for (bc.split.lens) |l| lc[blockLenCode(l).code] += 1;
        bc.type_code = try buildAndWriteCode(gpa, w, tc[0 .. nt + 2], nt + 2);
        bc.len_code = try buildAndWriteCode(gpa, w, &lc, tables.num_block_len_symbols);
        try bc.emitLen(w, bc.split.lens[0]);
    }

    fn emitLen(bc: *const BlockCodes, w: *BitWriter, len: u32) std.mem.Allocator.Error!void {
        const lc = blockLenCode(len);
        try bc.len_code.?.emit(w, lc.code);
        if (lc.nbits != 0) try w.writeBits(lc.extra, lc.nbits);
    }

    /// Before each symbol of the category.
    inline fn step(bc: *BlockCodes, w: *BitWriter) GiveUp!void {
        if (bc.split.ntypes == 1) return;
        if (bc.left == 0) {
            bc.b += 1;
            if (bc.b >= bc.split.lens.len) return error.EncoderInvariant;
            try bc.type_code.?.emit(w, bc.tcode[bc.b]);
            try bc.emitLen(w, bc.split.lens[bc.b]);
            bc.left = bc.split.lens[bc.b];
        }
        bc.left -= 1;
    }

    inline fn cur(bc: *const BlockCodes) u8 {
        return bc.split.types[bc.b];
    }

    /// Every block was used up.
    fn done(bc: *const BlockCodes) bool {
        if (bc.split.ntypes == 1) return true;
        return bc.b + 1 == bc.split.lens.len and bc.left == 0;
    }

    /// Bits of the block switches after the first block (codes built).
    fn switchBits(bc: *const BlockCodes) usize {
        if (bc.split.ntypes == 1) return 0;
        var bits: usize = 0;
        for (bc.tcode[1..], bc.split.lens[1..]) |c, l| {
            const lc = blockLenCode(l);
            bits += @as(usize, bc.type_code.?.len[c]) + bc.len_code.?.len[lc.code] + lc.nbits;
        }
        return bits;
    }
};

/// RFC 7932 §7.2: the distance code a copy's symbol is read with depends on
/// its length — 2, 3, 4, or more.
const dist_contexts = 4;

fn distContext(copy_len: u32) u2 {
    return @intCast(@min(copy_len, 5) -| 2);
}

/// Estimated bits of a histogram coded by its own prefix code: entropy plus
/// a header guess (`histogramCost`'s, for any alphabet).
fn sliceCost(h: []const u32) f64 {
    var total: u64 = 0;
    var used: u32 = 0;
    var sum: f64 = 0;
    for (h) |c| {
        if (c == 0) continue;
        total += c;
        used += 1;
        sum += nlog2n(c);
    }
    if (total == 0) return 0;
    return nlog2n(total) - sum + 40 + 5 * @as(f64, @floatFromInt(used));
}

/// Which distance contexts share a code: the cheapest of the 15 partitions
/// of the four, by `sliceCost` plus the context map's few bits. `map[ctx]`
/// is the code's number (assigned in order of first use); returns how many
/// codes.
fn clusterDistances(counts: *const [dist_contexts][dist_alphabet_max]u32, n_dist: usize, map: *[dist_contexts]u8) usize {
    // The cost of each non-empty set of contexts under one code, once: a
    // partition's groups are such sets (zeroing and summing per group of
    // each partition was 5 % of `.q6` on a 4 KiB font, 2026-10-16).
    var set_cost: [1 << dist_contexts]f64 = undefined;
    {
        var merged: [dist_alphabet_max]u32 = undefined;
        for (1..1 << dist_contexts) |set| {
            var rest = set & (set - 1);
            @memcpy(merged[0..n_dist], counts[@ctz(set)][0..n_dist]);
            while (rest != 0) : (rest &= rest - 1) {
                for (merged[0..n_dist], counts[@ctz(rest)][0..n_dist]) |*m, c| m.* += c;
            }
            set_cost[set] = sliceCost(merged[0..n_dist]);
        }
    }
    // Restricted growth strings over four items.
    var best: f64 = std.math.inf(f64);
    var best_map: [dist_contexts]u8 = @splat(0);
    var best_n: usize = 1;
    var cand: [dist_contexts]u8 = @splat(0);
    var code: usize = 0;
    while (code < 4 * 4 * 4) : (code += 1) {
        // Digits of `code` in base 4 are group ids of contexts 1..3; accept
        // only restricted growth (each id at most one above all before it).
        cand[0] = 0;
        var top: u8 = 0;
        var ok = true;
        for (1..dist_contexts) |k| {
            const g: u8 = @intCast((code >> @intCast(2 * (k - 1))) & 3);
            if (g > top + 1) {
                ok = false;
                break;
            }
            cand[k] = g;
            if (g > top) top = g;
        }
        if (!ok) continue;
        const groups: usize = top + 1;
        var cost: f64 = 0;
        for (0..groups) |g| {
            var set: usize = 0;
            for (cand, 0..) |c, ctx| set |= @as(usize, @intFromBool(c == g)) << @intCast(ctx);
            cost += set_cost[set];
        }
        if (groups > 1) cost += 12;
        if (cost < best) {
            best = cost;
            best_map = cand;
            best_n = groups;
        }
    }
    map.* = best_map;
    return best_n;
}

/// What a block's commands may name beyond its own output.
const BlockEnv = struct {
    /// How much further back than `input`'s start a copy may reach: the
    /// output dropped before it plus a prefix dictionary.
    reach: usize = 0,
    /// The stream has a large window (RFC 9841 §6): the larger distance
    /// alphabet.
    large_window: bool = false,
    /// Of `reach`, the output dropped (the rest is a prefix dictionary).
    dropped: usize = 0,
    /// The decoder's `max_backward` (window − 16): a dictionary word's
    /// distance counts from `min(output so far, max_backward)`.
    max_backward: usize = (1 << max_window_bits) - 16,
    /// NPOSTFIX/NDIRECT (never with a large window).
    dist: DistParams = .{},
    /// `Core.size_hint`.
    size_hint: usize = 0,
};

/// The bytes the dictionary word of command `c` stands for, made as the
/// decoder makes them, are `expect` (RFC 7932 §8); `pos` is the decoder's
/// output position before it. A word that would decode to anything else is
/// an encoder bug: the block is stored instead of carrying it.
fn checkWord(c: Cmd, pos: usize, env: BlockEnv, expect: []const u8) GiveUp!void {
    const n = c.copy_len;
    if (n < dictionary.min_word_length or n > dictionary.max_word_length) return error.EncoderInvariant;
    // Word ids start past a prefix dictionary (RFC 9841 §3.2).
    const dict_len = env.reach - env.dropped;
    const max_distance = @min(pos, env.max_backward) + dict_len;
    if (c.dist <= max_distance) return error.EncoderInvariant;
    const address = c.dist - max_distance - 1;
    const shift: u5 = @intCast(dictionary.size_bits_by_length[n]);
    const idx = address & ((@as(usize, 1) << shift) - 1);
    const t = address >> shift;
    if (t >= transforms.num_transforms) return error.EncoderInvariant;
    const word = dictionary.data[dictionary.offsets_by_length[n] + idx * n ..][0..n];
    var tmp: [transforms.maxOutputLen(dictionary.max_word_length)]u8 = undefined;
    const got = transforms.transformWord(&tmp, word, n, t);
    if (got != c.out_len or !std.mem.eql(u8, tmp[0..got], expect)) return error.EncoderInvariant;
}

const BlockResult = struct {
    /// The block used more than one literal code or literal block type.
    multi_literal: bool,
    /// With `multi_literal`: the same block with one literal code (and one
    /// literal block type) would be no longer (exact bits).
    single_no_worse: bool,
};

/// `writeCompressedBlock`, with a give-up (not OOM) as null: the caller
/// stores the block instead.
fn tryBlock(
    gpa: std.mem.Allocator,
    w: *BitWriter,
    input: []const u8,
    start: usize,
    end: usize,
    cmds: []const Cmd,
    is_last: bool,
    ring: *DistRing,
    effort: Effort,
    single_literal_code: bool,
    env: BlockEnv,
) std.mem.Allocator.Error!?BlockResult {
    return writeCompressedBlock(gpa, w, input, start, end, cmds, is_last, ring, effort, single_literal_code, env) catch |e| switch (e) {
        error.OutOfMemory => {
            // The caller's buffer ran out (`overflowed` stays set for
            // `Core.compressBlock`).
            if (!w.overflowed) return error.OutOfMemory;
            return null;
        },
        else => return null,
    };
}

/// The estimated bits of the distance symbols and extra bits `cmds` write
/// with parameters `p` (google `ComputeDistanceCost`), or null when one of
/// their distances has no code there.
fn distParamsCost(cmds: []const Cmd, ring0: DistRing, p: DistParams) ?f64 {
    var h: [dist_alphabet_max]u32 = @splat(0);
    const n = p.alphabet();
    var extra: f64 = 0;
    var ring = ring0;
    for (cmds) |c| {
        if (c.copy_len == 0) continue;
        const short: ?u16 = if (c.out_len == 0) ring.shortCode(c.dist) else null;
        if (c.out_len == 0) ring.update(c.dist, short);
        if (short) |code| {
            // An implicit-distance command reads no symbol; the estimate
            // counts code 0 anyway, as google's does not (it is the same
            // for every `p`).
            h[code] += 1;
            continue;
        }
        const dc = distanceCodeWith(c.dist, p, n) orelse return null;
        h[dc.sym] += 1;
        extra += @floatFromInt(dc.nbits);
    }
    return sliceCost(h[0..n]) + extra;
}

/// NPOSTFIX and NDIRECT for a meta-block of `cmds` (google
/// `BrotliBuildMetaBlock`'s search at qualities 10 and 11): for each
/// NPOSTFIX, NDIRECT grows while the distances' estimated bits fall.
fn chooseDistParams(cmds: []const Cmd, ring0: DistRing) DistParams {
    var best: DistParams = .{};
    var best_cost = distParamsCost(cmds, ring0, best) orelse return best;
    var msb: u32 = 0;
    var np: u32 = 0;
    while (np <= 3) : (np += 1) {
        while (msb < 16) : (msb += 1) {
            const p: DistParams = .{ .npostfix = @intCast(np), .ndirect = @intCast(msb << @intCast(np)) };
            const cost = distParamsCost(cmds, ring0, p) orelse break;
            if (cost > best_cost) break;
            best_cost = cost;
            best = p;
        }
        if (msb > 0) msb -= 1;
        msb /= 2;
    }
    return best;
}

/// Bit position after storing `n` bytes verbatim starting from bit `pos`.
fn storeCostBits(pos: usize, n: usize) usize {
    const mlen_minus_1 = n - 1;
    var size_nibbles: usize = 4;
    if (mlen_minus_1 >= (1 << 20)) {
        size_nibbles = 6;
    } else if (mlen_minus_1 >= (1 << 16)) {
        size_nibbles = 5;
    }
    const after_header = pos + 1 + 2 + size_nibbles * 4 + 1;
    return std.mem.alignForward(usize, after_header, 8) + n * 8;
}

/// Write one uncompressed (stored) meta-block. Always `ISLAST = 0`; the caller
/// terminates the stream with an empty final meta-block.
fn writeStoreBlock(w: *BitWriter, bytes: []const u8) std.mem.Allocator.Error!void {
    const mlen_minus_1: u32 = @intCast(bytes.len - 1);
    var size_nibbles: u6 = 4;
    if (mlen_minus_1 >= (1 << 20)) {
        size_nibbles = 6;
    } else if (mlen_minus_1 >= (1 << 16)) {
        size_nibbles = 5;
    }
    try w.writeBits(0, 1); // ISLAST = 0
    try w.writeBits(size_nibbles - 4, 2);
    try w.writeBits(mlen_minus_1, size_nibbles * 4);
    try w.writeBits(1, 1); // ISUNCOMPRESSED = 1
    try w.alignToByte();
    try w.writeBytes(bytes);
}

// ---------------------------------------------------------------------------
// Public API.

/// Compress `input` into a valid Brotli stream. Caller owns the returned slice.
///
/// Never fails except on allocation: any block the compressor cannot encode
/// (or cannot encode smaller than its raw bytes) is stored verbatim instead, so
/// the output is always a conformant `Content-Encoding: br` body.
pub fn compress(gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error![]u8 {
    return compressWith(gpa, input, .{});
}

/// How hard the encoder looks, named after the google/brotli quality (the
/// `quality` 0..11 of the C library and of the Go port) each level stands
/// in for: about that quality's compressed size, in at most about its time
/// (`tools/bench.zig` pairs `.qN` with quality N). The streams are not
/// byte-identical to the reference's; every level emits a valid stream and
/// falls back to storing a block that will not shrink. `.default` is `.q6`,
/// the Go port's `DefaultCompression`; `fromQuality` maps a quality level
/// from code written against the C or Go API.
pub const Effort = enum(u4) {
    /// google/brotli's quality 0, ported (`writeQ0`): one pass, each match
    /// written as found, codes from the block's bytes and the previous
    /// block; no dictionary. The fastest level.
    q0 = 0,
    /// One candidate per lookup (`FragMatcher`), the last distance tried at
    /// every position, matches extended backwards, a step that grows
    /// through data that stopped matching; one code per category.
    q1 = 1,
    /// Its own match finder (4 candidates, last distance), one literal
    /// code per block.
    q4 = 4,
    /// 32 candidates; literal context modelling (UTF8 / LSB6 modes).
    q6 = 6,
    /// 256 candidates, context modelling as `.q6`, block splitting. For
    /// content compressed once and served many times.
    q9 = 9,
    /// A shortest-path parse of every block priced from the block's own
    /// statistics, over 256 candidates. For content compressed once and
    /// served many times; several times `.q9`'s time.
    q11 = 11,

    pub const default: Effort = .q6;

    /// The level for a google/brotli quality: the nearest one at or above
    /// it (a caller asking for quality 7 gets at least quality 7's ratio),
    /// `.q11` past 11.
    pub fn fromQuality(q: u32) Effort {
        if (q == 0) return .q0;
        if (q == 1) return .q1;
        if (q <= 4) return .q4;
        if (q <= 6) return .q6;
        if (q <= 9) return .q9;
        return .q11;
    }

    /// The google/brotli quality this level stands in for.
    pub fn quality(e: Effort) u4 {
        return @intFromEnum(e);
    }

    const Finder = enum { frag, fast, deep };

    /// Whether the level searches a prefix dictionary: all but `.q0`
    /// (google/brotli's quality 0, ported, looks at the input only).
    /// google searches one only from quality 5.
    pub fn searchesDictionary(e: Effort) bool {
        return e != .q0;
    }

    /// The match finder an effort uses.
    fn finder(e: Effort) Finder {
        return switch (e) {
            .q0, .q1 => .frag,
            .q4 => .fast,
            .q6, .q9, .q11 => .deep,
        };
    }

    /// log2 of all bucket slots together, the match finder's table, for an
    /// input of `size` bytes: 2^`per_byte` slots a byte, up to a cap. Sized
    /// to the input because every call gets a fresh table, and a fresh page
    /// costs a fault when first touched: at one bucket per byte (the sizing
    /// until 2026-10-15) the positions of a 16 KiB input landed on every
    /// page of `.q6`'s 2 MiB, most of its time (R16). The fuller buckets of
    /// a smaller table are what every input past the cap has anyway; sizes
    /// moved by ±0.3 % on 4–64 KiB slices of text, HTML, JSON and a font.
    /// `.q9`'s cap is 2^22 slots, 16 MiB (google q9: 2^15 buckets of 256,
    /// 32 MiB): at 2^20 a 1.3–5.8 MB text walked buckets of positions that
    /// share no more than their hash bits, at 1.2–1.6× google's time and
    /// 0.3–1.2 % larger (2026-10-16); inputs under 512 KiB are unchanged.
    fn slotsLog(e: Effort, size: usize) u5 {
        const cap: u5, const per_byte: u5 = switch (e) {
            .q0, .q1, .q4 => unreachable, // `FragMatcher`, `FastMatcher`
            .q6 => .{ 19, 2 },
            .q9 => .{ 22, 3 },
            .q11 => .{ 22, 3 },
        };
        const size_log = std.math.log2_int_ceil(usize, @max(size, 1));
        return @intCast(@min(cap, size_log + per_byte));
    }

    /// log2 of `WideMatcher`'s slots: google's 2^15 buckets of
    /// 2^(quality - 1) — `.q6` 32 a bucket (4 MiB), `.q9` 256 (32 MiB).
    fn wideSlotsLog(e: Effort) u5 {
        return switch (e) {
            .q6 => 15 + 5,
            .q9 => 15 + 8,
            else => unreachable, // `Core.kindFor`
        };
    }

    fn depth(e: Effort) u32 {
        return switch (e) {
            .q0, .q1, .q4 => unreachable, // `FragMatcher`, `FastMatcher`
            .q6 => 32,
            .q9 => 256,
            .q11 => 256,
        };
    }
};

pub const CompressOptions = struct {
    effort: Effort = .default,
    /// Input bytes per meta-block (1..1 MiB). Each block gets its own codes:
    /// smaller blocks adapt to changing data but pay more headers.
    block_size: usize = default_block_size,
    /// log2 of the window (`min_window_bits`..`max_window_bits`): how far
    /// back a copy may reach, and how much history a decoder must keep. Null:
    /// 16 for an input of up to 65 520 bytes, else 21. Above
    /// `max_window_bits`, to `max_large_window_bits`: a large-window stream
    /// (RFC 9841 §6), for decoders that ask for one — not a web `br` body.
    window_bits: ?u5 = null,
    /// A raw prefix dictionary (RFC 9841 §3.2; RFC 9842 `dcb`): bytes copies
    /// may come from as if they preceded the input; the decoder needs the
    /// same (`Options.dictionary`). Prepared for the call (`PreparedDictionary`:
    /// O(its length) each time) and searched beside the input from `.q1`
    /// on; `.q0` looks only at the input, as google/brotli's quality 0 does
    /// (its stream still needs the dictionary to decode: static-dictionary
    /// words count past it). For many compressions against one dictionary,
    /// `prepared_dictionary`.
    dictionary: []const u8 = &.{},
    /// `dictionary`, prepared once (`PreparedDictionary.init`), for any
    /// number of compressions: the same bytes as passing its `source` as
    /// `dictionary`. Not both.
    prepared_dictionary: ?*const PreparedDictionary = null,

    pub const default_block_size = compressed_block_size;
};

/// RFC 7932 §9.1: WBITS 10..24; above, to `max_large_window_bits`, a
/// large-window stream (RFC 9841 §6) — which only a decoder asked for one
/// accepts (ours: `Options.large_window`), not a browser's `br`.
pub const min_window_bits = 10;
pub const max_large_window_bits = 30;
/// MSKIPLEN's largest value (three bytes).
const max_metadata_block = 1 << 24;
pub const max_window_bits = 24;

/// `compress` with options.
pub fn compressWith(gpa: std.mem.Allocator, input: []const u8, opts: CompressOptions) std.mem.Allocator.Error![]u8 {
    var core = try Core.init(gpa, opts.effort, opts.block_size, windowBits(input.len, opts), tableSize(input.len, windowBits(input.len, opts)), input.len);
    defer core.deinit();
    try oneShot(&core, input, opts);
    return core.w.buf.toOwnedSlice(gpa);
}

/// `CompressOptions.window_bits` or its default for an input of `n` bytes.
fn windowBits(n: usize, opts: CompressOptions) u5 {
    return opts.window_bits orelse if (n > 65520) 21 else 16;
}

/// What the match finder's table is sized for: the input, but no more than
/// the window, which is all of it a copy can reach — and what a stream
/// (`StreamWriter`) sizes for, so the two give the same bytes. (A prefix
/// dictionary has a table of its own.)
pub fn tableSize(input_len: usize, wbits: u5) usize {
    return @min(input_len, @as(usize, 1) << wbits);
}

pub const CompressIntoError = std.mem.Allocator.Error || error{
    /// The stream does not fit `out`; `out` holds a partial one.
    OutputTooLarge,
};

/// `compressWith` into the caller's buffer: returns the stream, a prefix of
/// `out`. No output allocation (`gpa` holds the match finder's table and a
/// block's prefix codes). The stream is the one `compressWith` gives; it
/// fails only when that does not fit — `maxCompressedSize` is always
/// enough.
pub fn compressInto(gpa: std.mem.Allocator, out: []u8, input: []const u8, opts: CompressOptions) CompressIntoError![]u8 {
    var core = try Core.init(gpa, opts.effort, opts.block_size, windowBits(input.len, opts), tableSize(input.len, windowBits(input.len, opts)), input.len);
    defer core.deinit();
    return oneShotInto(&core, out, input, opts);
}

/// An encoder kept from call to call (zstd's `Compressor`; google/brotli's
/// encoder state, which glibc's malloc keeps warm for it): `compress` and
/// `compressInto` give the bytes `compressWith` and `compressInto` give, but
/// the match finder's tables, the block's buffers and `.q11`'s index of the
/// static dictionary stay between calls (`Core.reinit`). For many small
/// compressions under an allocator that returns big blocks to the kernel
/// (`std.heap.smp_allocator` maps anything over its size classes afresh):
/// `.q6`'s table for a 16 KiB input is 256 KiB, and mapping, faulting in
/// and unmapping it cost 1.1–2.4× google's time at 4–64 KiB (R16). Not
/// for concurrent use; one per thread.
pub const Compressor = struct {
    gpa: std.mem.Allocator,
    core: ?Core = null,

    /// Allocates nothing until the first call.
    pub fn init(gpa: std.mem.Allocator) Compressor {
        return .{ .gpa = gpa };
    }

    pub fn deinit(c: *Compressor) void {
        if (c.core) |*k| k.deinit();
        c.* = undefined;
    }

    /// `compressWith(gpa, input, opts)`. Caller owns the result: a copy
    /// of the stream, the buffer it grew in kept for the next call (a
    /// buffer grown anew each call walks the allocator's size classes, and
    /// Zig 0.16's `smp_allocator` leaks on that walk — std defect: about 2
    /// KB for every `ArrayList` grown to a few KB and freed, one thread,
    /// 2026-10-16; see `Core.temp`).
    pub fn compress(c: *Compressor, input: []const u8, opts: CompressOptions) std.mem.Allocator.Error![]u8 {
        const core = try c.ready(input.len, opts);
        try oneShot(core, input, opts);
        return c.gpa.dupe(u8, core.w.buf.items);
    }

    /// `compressInto(gpa, out, input, opts)`.
    pub fn compressInto(c: *Compressor, out: []u8, input: []const u8, opts: CompressOptions) CompressIntoError![]u8 {
        const core = try c.ready(input.len, opts);
        // `out` stands in for the kept buffer for this call.
        const own = core.w.buf;
        defer {
            core.w.buf = own;
            core.w.fixed = false;
            core.w.overflowed = false;
        }
        return oneShotInto(core, out, input, opts);
    }

    fn ready(c: *Compressor, n: usize, opts: CompressOptions) std.mem.Allocator.Error!*Core {
        const wbits = windowBits(n, opts);
        if (c.core) |*k| {
            try k.reinit(opts.effort, opts.block_size, wbits, tableSize(n, wbits), n);
            return k;
        }
        c.core = try Core.init(c.gpa, opts.effort, opts.block_size, wbits, tableSize(n, wbits), n);
        c.core.?.keep_temp = true;
        return &c.core.?;
    }
};

fn oneShotInto(core: *Core, out: []u8, input: []const u8, opts: CompressOptions) CompressIntoError![]u8 {
    core.w.buf = .initBuffer(out);
    core.w.fixed = true;
    oneShot(core, input, opts) catch |e| return if (core.w.overflowed) error.OutputTooLarge else e;
    return core.w.buf.items;
}

/// The longest stream `compressWith(_, input, opts)` can give for an input
/// of `n` bytes: every block stored, plus the final empty meta-block (a
/// compressed block is kept only when it is shorter than stored). Exact:
/// incompressible input reaches it.
pub fn maxCompressedSize(n: usize, opts: CompressOptions) usize {
    const wbits: u5 = opts.window_bits orelse if (n > 65520) 21 else 16;
    var bits: usize = if (wbits > max_window_bits) 14 else if (wbits == 16) 1 else if (wbits >= 18) 4 else 7;
    var off: usize = 0;
    while (off < n) {
        const k = @min(n - off, opts.block_size);
        bits = storeCostBits(bits, k);
        off += k;
    }
    return (bits + 2 + 7) / 8;
}

/// The header, every block of `input`, the end — against `opts`'s
/// dictionary, prepared here when it is raw.
fn oneShot(core: *Core, input: []const u8, opts: CompressOptions) std.mem.Allocator.Error!void {
    std.debug.assert(opts.dictionary.len == 0 or opts.prepared_dictionary == null);
    var own: ?PreparedDictionary = null;
    defer if (own) |*d| d.deinit(core.gpa);
    if (opts.prepared_dictionary) |d| {
        core.attachDictionary(d);
    } else if (opts.dictionary.len != 0) {
        if (core.effort.searchesDictionary()) {
            own = try PreparedDictionary.initOptions(core.gpa, opts.dictionary, .{ .digest = false });
            core.attachDictionary(&own.?);
        } else core.dict_len = opts.dictionary.len;
    }
    core.size_hint = input.len;
    core.setData(input);
    try core.writeHeader();
    var off: usize = 0;
    while (off < input.len) {
        const end = off + @min(input.len - off, opts.block_size);
        try core.compressBlock(off, end, end == input.len);
        off = end;
    }
    try core.finish();
}

/// The encoder's state across meta-blocks, one-shot (`compressWith`) or
/// streamed (`StreamWriter`): one encoding logic for both, so a stream cut
/// at the same blocks is the same bytes.
pub const Core = struct {
    gpa: std.mem.Allocator,
    effort: Effort,
    block_size: usize,
    wbits: u5,
    matcher: union(Kind) { frag: FragMatcher, fast: FastMatcher, deep: Matcher, wide: WideMatcher },
    /// The input so far that copies may reach (`compressBlock`'s positions
    /// index it).
    data: []const u8 = &.{},
    /// Output: whole bytes in `w.buf`, up to 31 bits pending.
    w: BitWriter,
    /// The single-literal-code alternative of a block is written here.
    alt: BitWriter,
    /// A block that overflowed the caller's buffer is decided here.
    scratch: BitWriter,
    cmds: std.ArrayListUnmanaged(Cmd) = .empty,
    /// `.q0`/`.q1`: the block's commands, resolved (`buildFrag`).
    frag: FragBlock = .{},
    /// `.q11`: the parses of a block (`buildCommandsOptimal`), and the writer
    /// that sizes each.
    parses: [max_parses]std.ArrayListUnmanaged(Cmd) = @splat(.empty),
    trial: BitWriter,
    /// `.q11`: the static dictionary's index (`DictSearch`), made on first use.
    dict_search: ?DictSearch = null,
    /// The decoder's last four distances after the blocks so far.
    ring: DistRing = .{},
    /// The last block written was ISLAST.
    emitted_last: bool = false,
    /// `tableLog` the tables were made with.
    table_log: u6,
    /// `.q0`'s command and distance codes for the next block, those a block
    /// ends with (`writeQ0`), and its last meta-block's counts.
    q0: Q0Codes = .default,
    q0_next: Q0Codes = .default,
    q0_histo: [128]u32 = q0_cmd_histo_seed,
    /// The whole input's length when known (google's `size_hint`): from
    /// 1 MiB `.q6`/`.q9` may take thirteen literal contexts
    /// (`greedy_split.chooseStaticContexts`). One-shot: the input; a stream:
    /// `StreamOptions.size_hint`, else 0.
    size_hint: usize = 0,
    /// The prefix dictionary's length (`attachDictionary`), 0 without:
    /// static-dictionary words count past it, at every level.
    dict_len: usize = 0,
    /// The match finder's tables (the matcher's views into it).
    table_mem: []u32,
    /// `reinit`s in a row whose tables needed under a third of `table_mem`.
    oversized: u8 = 0,
    /// The block writer's short-lived allocations (`tempAlloc`) when the
    /// core outlives one input (`keep_temp`: `Compressor`, `StreamWriter`):
    /// its codes, histograms and context models come and go dozens of times
    /// a block, and kept between blocks and calls they cost the allocator
    /// nothing after the first. Under Zig 0.16's `smp_allocator` that also
    /// stops a leak (std defect, 2026-10-16: a thread that runs out of a
    /// size class moves to another thread slot's free lists for good —
    /// `max_alloc_search` 1 — and what it freed before stays behind, so the
    /// 16 and 32 KiB classes got a new 64 KiB slab on every call: `.q4` on a
    /// 4 KiB input grew by 41 KB a call, `compressWith` or not). A one-shot
    /// core allocates from `gpa` as before: an arena made anew per call
    /// leaked more (its growing blocks hit the same classes), at every
    /// level.
    temp: std.heap.ArenaAllocator,
    keep_temp: bool = false,

    /// `size`: how much input the match finder's tables are sized for.
    /// `size_hint`: the whole input's length when known (`Core.size_hint`),
    /// else 0.
    pub fn init(gpa: std.mem.Allocator, effort: Effort, block_size: usize, wbits: u5, size: usize, size_hint: usize) std.mem.Allocator.Error!Core {
        const k = kindFor(effort, wbits, size_hint);
        const mem = try gpa.alloc(u32, tableLen(effort, k, size));
        return fresh(gpa, effort, block_size, wbits, size, size_hint, mem);
    }

    /// The match finder `init` gives `effort`: google/brotli's hasher for
    /// large inputs (`WideMatcher`: H68 at q5–q7, H6 at q8–q9) where google
    /// picks it — a size hint of 1 MiB or more and a window of 19 bits or
    /// more (`ChooseHasher`), not a large window (google's H65 there, not
    /// ported) — else the effort's own (R14, 2026-10-16).
    fn kindFor(effort: Effort, wbits: u5, size_hint: usize) Kind {
        return switch (effort.finder()) {
            .frag => .frag,
            .fast => .fast,
            .deep => if ((effort == .q6 or effort == .q9) and size_hint >= 1 << 20 and wbits >= 19 and wbits <= max_window_bits) .wide else .deep,
        };
    }

    const Kind = enum { frag, fast, deep, wide };

    fn kind(c: *const Core) Kind {
        return std.meta.activeTag(c.matcher);
    }

    /// `init`'s state on `mem` (at least `tableLen` long).
    fn fresh(gpa: std.mem.Allocator, effort: Effort, block_size: usize, wbits: u5, size: usize, size_hint: usize, mem: []u32) Core {
        std.debug.assert(block_size >= 1 and block_size <= compressed_block_size);
        std.debug.assert(wbits >= min_window_bits and wbits <= max_large_window_bits);
        const k = kindFor(effort, wbits, size_hint);
        return .{
            .gpa = gpa,
            .effort = effort,
            .block_size = block_size,
            .wbits = wbits,
            .matcher = switch (k) {
                .frag => .{ .frag = FragMatcher.initIn(mem, size) },
                .fast => .{ .fast = FastMatcher.initIn(mem, size) },
                .deep => .{ .deep = Matcher.initIn(mem, effort.depth(), effort.slotsLog(size)) },
                .wide => .{ .wide = WideMatcher.initIn(mem, effort.depth(), effort.wideSlotsLog()) },
            },
            .w = .{ .gpa = gpa },
            .alt = .{ .gpa = gpa },
            .scratch = .{ .gpa = gpa },
            .trial = .{ .gpa = gpa },
            .table_log = tableLog(effort, k, size),
            .table_mem = mem,
            .temp = .init(gpa),
            .size_hint = size_hint,
        };
    }

    /// The block writer's allocator: `temp`, emptied (its memory kept), or
    /// `gpa` for a one-shot core. What it hands out lives until the next
    /// call.
    fn tempAlloc(c: *Core) std.mem.Allocator {
        if (!c.keep_temp) return c.gpa;
        _ = c.temp.reset(.retain_capacity);
        return c.temp.allocator();
    }

    /// The `u32`s of the match finder's tables `init` makes.
    fn tableLen(effort: Effort, k: Kind, size: usize) usize {
        return switch (k) {
            .frag => FragMatcher.tableLen(size),
            .fast => FastMatcher.tableLen(size),
            .deep => Matcher.tableLen(effort.depth(), effort.slotsLog(size)),
            .wide => WideMatcher.tableLen(effort.depth(), effort.wideSlotsLog()),
        };
    }

    /// As `init` with these arguments leaves a core — the next stream's
    /// bytes are the ones a fresh core gives — but on this one's memory:
    /// its tables, while big enough (and not, 128 times in a row, more than
    /// three times what is needed), and the buffers a block is written
    /// with. For many small compressions, where a fresh table costs more
    /// than compressing (`Compressor`, R16).
    pub fn reinit(c: *Core, effort: Effort, block_size: usize, wbits: u5, size: usize, size_hint: usize) std.mem.Allocator.Error!void {
        const gpa = c.gpa;
        const need = tableLen(effort, kindFor(effort, wbits, size_hint), size);
        var mem = c.table_mem;
        var oversized: u8 = 0;
        if (mem.len >= need and mem.len / 3 > need) oversized = c.oversized +| 1;
        if (mem.len < need or oversized > 128) {
            gpa.free(mem);
            c.table_mem = &.{};
            mem = try gpa.alloc(u32, need);
            c.table_mem = mem;
            oversized = 0;
        }
        var n = fresh(gpa, effort, block_size, wbits, size, size_hint, mem);
        n.oversized = oversized;
        // The block's buffers, emptied; the output's only when it is ours.
        inline for (.{ "alt", "scratch", "trial" }) |f| {
            @field(n, f).buf = @field(c, f).buf;
            @field(n, f).buf.clearRetainingCapacity();
        }
        if (!c.w.fixed) {
            n.w.buf = c.w.buf;
            n.w.buf.clearRetainingCapacity();
        }
        n.cmds = c.cmds;
        n.cmds.clearRetainingCapacity();
        n.frag = c.frag;
        n.parses = c.parses;
        // Static data: the same index for any input.
        n.dict_search = c.dict_search;
        n.temp = c.temp;
        n.keep_temp = c.keep_temp;
        c.* = n;
    }

    pub fn deinit(c: *Core) void {
        c.gpa.free(c.table_mem);
        c.temp.deinit();
        if (!c.w.fixed) c.w.buf.deinit(c.gpa);
        c.alt.buf.deinit(c.gpa);
        c.scratch.buf.deinit(c.gpa);
        c.cmds.deinit(c.gpa);
        c.frag.deinit(c.gpa);
        for (&c.parses) |*l| l.deinit(c.gpa);
        if (c.dict_search) |*d| d.deinit(c.gpa);
        c.trial.buf.deinit(c.gpa);
        c.* = undefined;
    }

    pub fn history(c: *const Core) History {
        return switch (c.kind()) {
            .frag => c.matcher.frag.history,
            .fast => c.matcher.fast.history,
            .deep => c.matcher.deep.history,
            .wide => c.matcher.wide.history,
        };
    }

    fn setHistory(c: *Core, x: History) void {
        switch (c.kind()) {
            .frag => c.matcher.frag.history = x,
            .fast => c.matcher.fast.history = x,
            .deep => c.matcher.deep.history = x,
            .wide => c.matcher.wide.history = x,
        }
    }

    /// Compress against `d` (RFC 9841 §3.2), which must outlive the
    /// stream: searched from `.q1` on (`Effort.searchesDictionary`).
    /// Before the first block.
    pub fn attachDictionary(c: *Core, d: *const PreparedDictionary) void {
        c.dict_len = d.source.len;
        if (d.source.len == 0) return;
        if (!c.effort.searchesDictionary()) return;
        switch (c.kind()) {
            .frag => c.matcher.frag.dict = .{ .pd = d },
            .fast => c.matcher.fast.dict = .{ .pd = d },
            .deep => {
                c.matcher.deep.dict = .{ .pd = d };
                c.matcher.deep.dict_len = d.source.len;
            },
            .wide => {
                c.matcher.wide.dict = .{ .pd = d };
                c.matcher.wide.dict_len = d.source.len;
            },
        }
    }

    /// A dictionary is searched (`attachDictionary`).
    fn searching(c: *const Core) bool {
        return switch (c.kind()) {
            .frag => c.matcher.frag.dict != null,
            .fast => c.matcher.fast.dict != null,
            .deep => c.matcher.deep.dict != null,
            .wide => c.matcher.wide.dict != null,
        };
    }

    /// The `bucketLog` `init` gives an effort's tables for `size`.
    fn tableLog(effort: Effort, k: Kind, size: usize) u6 {
        return switch (k) {
            .frag => bucketLog(size, frag_bucket_log_max),
            .fast => bucketLog(size, fast_bucket_log_max),
            .deep => Matcher.bucketLogFor(effort.depth(), effort.slotsLog(size)),
            .wide => WideMatcher.bucketLogFor(effort.depth(), effort.wideSlotsLog()),
        };
    }

    /// `data` will lose its first `by` bytes (`setData` follows).
    pub fn shift(c: *Core, by: usize) void {
        switch (c.kind()) {
            .frag => c.matcher.frag.shift(@intCast(by)),
            .fast => c.matcher.fast.shift(@intCast(by)),
            .deep => c.matcher.deep.shift(@intCast(by)),
            .wide => c.matcher.wide.shift(@intCast(by)),
        }
    }

    /// RFC 7932 §9.2 has no flush marker; an empty metadata meta-block
    /// (ISLAST 0, MNIBBLES 0, reserved 0, MSKIPBYTES 0 — six bits, as
    /// google/brotli's flush writes) ends at a byte boundary, so every bit
    /// so far can go out. Nothing when the output is already byte aligned.
    pub fn flushToByte(c: *Core) std.mem.Allocator.Error!void {
        if (c.w.cnt % 8 != 0) try c.w.writeBits(0b000110, 6);
        try c.w.alignToByte();
    }

    /// Metadata meta-blocks carrying `bytes` (RFC 7932 §9.2: a decoder
    /// skips them), at most 2^24 bytes each. Precondition: no meta-block
    /// open (between `compressBlock`s).
    pub fn writeMetadata(c: *Core, bytes: []const u8) std.mem.Allocator.Error!void {
        var rest = bytes;
        while (true) {
            const n = @min(rest.len, max_metadata_block);
            // ISLAST 0, MNIBBLES 0 (code 3), reserved 0.
            try c.w.writeBits(0b110, 4);
            // MSKIPBYTES: the fewest bytes MSKIPLEN - 1 fits (a top byte of
            // zero is invalid), none for an empty block.
            var nbytes: u6 = 0;
            if (n != 0) {
                const v: u32 = @intCast(n - 1);
                nbytes = if (v < 1 << 8) 1 else if (v < 1 << 16) 2 else 3;
                try c.w.writeBits(@intCast(nbytes), 2);
                try c.w.writeBits(v, nbytes * 8);
            } else try c.w.writeBits(0, 2);
            try c.w.alignToByte();
            try c.w.writeBytes(rest[0..n]);
            rest = rest[n..];
            if (rest.len == 0) return;
        }
    }

    pub fn setData(c: *Core, data: []const u8) void {
        c.data = data;
        switch (c.kind()) {
            .frag => c.matcher.frag.data = data,
            .fast => c.matcher.fast.data = data,
            .deep => c.matcher.deep.setData(data),
            .wide => c.matcher.wide.setData(data),
        }
    }

    /// WBITS (RFC 7932 §9.1): a single 0 bit for 16; 1 + (wbits - 17) in
    /// three bits for 18..24; for 17 and 10..15, 1 + 000 + three more bits:
    /// 000 for 17, else wbits - 8.
    pub fn writeHeader(c: *Core) std.mem.Allocator.Error!void {
        if (c.wbits > max_window_bits) {
            // RFC 9841 §6: 1, 000, 100 (n2 = 1), 0, then six bits of WBITS.
            try c.w.writeBits(0b0010001, 8);
            try c.w.writeBits(c.wbits, 6);
        } else if (c.wbits == 16) {
            try c.w.writeBits(0, 1);
        } else if (c.wbits >= 18) {
            try c.w.writeBits(1, 1);
            try c.w.writeBits(c.wbits - 17, 3);
        } else {
            try c.w.writeBits(1, 1);
            try c.w.writeBits(0, 3);
            try c.w.writeBits(if (c.wbits == 17) 0 else c.wbits - 8, 3);
        }
    }

    /// One meta-block for `data[off..end)`: compressed when that is shorter
    /// than storing it, else stored.
    pub fn compressBlock(c: *Core, off: usize, end: usize, is_last: bool) std.mem.Allocator.Error!void {
        const gpa = c.gpa;
        const n = end - off;
        const max_dist = (@as(usize, 1) << c.wbits) - 16;
        c.cmds.clearRetainingCapacity();
        switch (c.effort) {
            // `.q0` parses as it writes (`writeQ0`, from `writeBest`).
            .q0 => {},
            inline .q1 => |e| if (c.searching())
                try buildFrag(true, comptime fragLevel(e), gpa, &c.matcher.frag, off, end, max_dist, c.ring, &c.frag)
            else
                try buildFrag(false, comptime fragLevel(e), gpa, &c.matcher.frag, off, end, max_dist, c.ring, &c.frag),
            .q4 => if (c.searching())
                try buildCommandsFast(true, gpa, &c.matcher.fast, off, end, max_dist, c.ring, &c.cmds)
            else
                try buildCommandsFast(false, gpa, &c.matcher.fast, off, end, max_dist, c.ring, &c.cmds),
            .q11 => {
                const n_dist: usize = if (c.wbits > max_window_bits) dist_alphabet_large else dist_alphabet_size;
                // Built once per encoder, on its first such block.
                if (c.dict_search == null) c.dict_search = try DictSearch.init(gpa);
                switch (c.matcher.deep.tagsPay(c.data[off..end])) {
                    inline else => |tagged| if (c.searching())
                        try buildCommandsOptimal(true, tagged, gpa, c.tempAlloc(), &c.matcher.deep, off, end, max_dist, c.ring, n_dist, &c.dict_search.?, &c.parses)
                    else
                        try buildCommandsOptimal(false, tagged, gpa, c.tempAlloc(), &c.matcher.deep, off, end, max_dist, c.ring, n_dist, &c.dict_search.?, &c.parses),
                }
                // The shortest as written wins: the estimate the parses were
                // priced by is not the code that comes out.
                var best_k: usize = 0;
                var best_bits: usize = std.math.maxInt(usize);
                const own = c.cmds;
                for (&c.parses, 0..) |*l, k| {
                    c.cmds = l.*;
                    c.trial.resumeAt(c.w.mark());
                    var ring = c.ring;
                    const ok = try c.writeBest(&c.trial, c.trial.mark(), off, end, is_last, &ring);
                    if (ok and c.trial.bitPos() < best_bits) {
                        best_bits = c.trial.bitPos();
                        best_k = k;
                    }
                }
                c.cmds = own;
                std.mem.swap(std.ArrayListUnmanaged(Cmd), &c.cmds, &c.parses[best_k]);
            },
            inline .q6, .q9 => |e| {
                // `.q6` skips through long literal runs (fonts: 15 %
                // of its time for ±0.25 % of size); `.q9` looks at every
                // position, and for a static-dictionary word where no copy
                // is found. (Words at `.q6` too, as google/brotli from q5:
                // text −0.7 %, small UTF-8 −7.5 %, for 5–10 % of its time —
                // left out by the owner, 2026-10-15.)
                const skip: usize = if (e == .q6) 64 else std.math.maxInt(usize);
                const simd = e == .q6;
                const px = c.searching();
                switch (c.matcher) {
                    inline .deep, .wide => |*mt| {
                        mt.ring = c.ring;
                        switch (mt.tagsPay(c.data[off..end])) {
                            inline else => |tagged| if (px)
                                try buildCommands(4, skip, true, tagged, simd, e == .q9, gpa, mt, off, end, max_dist, &c.cmds)
                            else
                                try buildCommands(4, skip, false, tagged, simd, e == .q9, gpa, mt, off, end, max_dist, &c.cmds),
                        }
                    },
                    else => unreachable,
                }
            },
        }

        const w = &c.w;
        const m = w.mark();
        const store_bits = storeCostBits(w.bitPos(), n);
        var trial = c.ring;
        var ok = try c.writeBest(w, m, off, end, is_last, &trial);
        if (!ok and w.overflowed) {
            // The caller's buffer (`compressInto`) ran out mid-block. Decide
            // in a scratch writer, as `compressWith` would, and copy the
            // winner — when it is kept, it fits wherever the stored block
            // would (it is shorter).
            w.overflowed = false;
            w.rollback(m);
            c.scratch.resumeAt(m);
            trial = c.ring;
            ok = try c.writeBest(&c.scratch, c.scratch.mark(), off, end, is_last, &trial);
            ok = ok and m.len * 8 + c.scratch.bitPos() < store_bits;
            if (ok) try w.takeFrom(m, &c.scratch);
        }
        if (c.effort == .q0 and !is_last) {
            // google: the next block starts from this one's codes, stored or
            // not (after the last, a stream's `reset` starts from the
            // defaults).
            c.q0 = c.q0_next;
            q0PrepareCommandCodes(c.tempAlloc(), &c.q0_histo, &c.q0) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => c.q0 = .default,
            };
        }
        if (ok and w.bitPos() < store_bits) {
            c.ring = trial; // a stored block leaves the decoder's ring alone
            // `.q0`'s meta-blocks are never ISLAST: `finish` adds one.
            c.emitted_last = is_last and c.effort != .q0;
        } else {
            w.rollback(m);
            try writeStoreBlock(w, c.data[off..end]);
            c.emitted_last = false;
        }
    }

    /// The block as compressed meta-block after `dm` in `dst`: the context
    /// model's, or one literal code when that is really shorter; false when
    /// the encoder gave up on it (or `dst`, the caller's buffer, ran out:
    /// `overflowed`). `ring`: the decoder's ring after it.
    fn writeBest(c: *Core, dst: *BitWriter, dm: BitWriter.Mark, off: usize, end: usize, is_last: bool, ring: *DistRing) std.mem.Allocator.Error!bool {
        var trial = c.ring;
        // The block writer sees the output only: literal contexts at its
        // start are zeros, as the decoder's (a dictionary is not output).
        const x = c.history();
        const out = c.data;
        var env: BlockEnv = .{ .reach = c.dict_len + x.dropped, .large_window = c.wbits > max_window_bits, .dropped = x.dropped, .max_backward = (@as(usize, 1) << c.wbits) - 16, .size_hint = c.size_hint };
        if (c.effort == .q0) {
            var codes = c.q0;
            writeQ0(c.tempAlloc(), dst, c.data[off..end], c.matcher.frag.table, env.max_backward, &codes, &c.q0_histo) catch |e| switch (e) {
                error.OutOfMemory => if (dst.overflowed) return false else return error.OutOfMemory,
                else => return false,
            };
            c.q0_next = codes;
            ring.* = c.ring; // `.q0` never writes a ring distance it did not write itself
            return true;
        }
        if (c.effort.finder() == .frag) {
            writeFragmentBlock(c.tempAlloc(), dst, &c.frag, end - off, is_last, env.large_window, storeCostBits(dst.bitPos(), end - off)) catch |e| switch (e) {
                error.OutOfMemory => if (dst.overflowed) return false else return error.OutOfMemory,
                else => return false,
            };
            ring.* = c.frag.ring;
            return true;
        }
        if (c.effort == .q11 and !env.large_window) env.dist = chooseDistParams(c.cmds.items, c.ring);
        const first = (try tryBlock(c.tempAlloc(), dst, out, off, end, c.cmds.items, is_last, &trial, c.effort, false, env)) orelse return false;
        // The context model was chosen on estimated bits. When it split the
        // literals, write the block once more with a single literal code and
        // keep whichever is really shorter (a flat, small alphabet is where
        // the estimate overfits: `alpha5_flat` came out 1.4 % larger with
        // contexts than without).
        // `writeCompressedBlock` prices that alternative on exact bits, so it
        // is written only when it wins — to `alt`, resumed at the same bit,
        // and spliced in. The real write still decides (`ctx_bits` below).
        if (first.multi_literal and first.single_no_worse) {
            const ctx_bits = dst.bitPos() - dm.len * 8;
            c.alt.resumeAt(dm);
            var single_ring = c.ring;
            const single = try tryBlock(c.tempAlloc(), &c.alt, out, off, end, c.cmds.items, is_last, &single_ring, c.effort, true, env);
            if (single != null and ctx_bits >= c.alt.bitPos()) {
                try dst.takeFrom(dm, &c.alt);
                trial = single_ring;
            }
        }
        ring.* = trial;
        return true;
    }

    /// End the stream: the final empty meta-block unless the last block was
    /// ISLAST, then the last byte.
    pub fn finish(c: *Core) std.mem.Allocator.Error!void {
        if (!c.emitted_last) {
            // ISLAST = 1, ISLASTEMPTY = 1.
            try c.w.writeBits(1, 1);
            try c.w.writeBits(1, 1);
        }
        try c.w.alignToByte();
    }
};

// ===========================================================================
// Tests — the writer's own invariants.
//
// The two helpers below (`readComplexCode` and `replayCodeLengths`) mirror
// `Decoder.readComplexHuffman`, which is file-private and must not be made
// public just to be testable. They deliberately reuse the decoder's *own*
// primitives — `BitReader`, `huffman.buildComplex`, and the `tables.zig`
// constants — so what is re-stated here is only the loop shape, not the format
// data. That is enough to catch any mutation of the WRITER, which is what these
// tests are for; it is NOT enough to catch a misreading of RFC 7932 shared by
// this file and `decoder.zig`. That class of bug is caught only in
// `tools/interop.zig`, where google/brotli decodes what we emit — and, once
// captured, in `interop_replay_test.zig`, which pins the digest of every
// stream it accepted.
// ===========================================================================

const testing = std.testing;
const BitReader = @import("bitreader.zig").BitReader;

const ReadBackError = error{
    RanOut,
    WrongExtraWidth,
    ExtraOutOfRange,
    Overflow,
    Incomplete,
    TrailingItems,
    BadHskip,
    BadCodeLengthCode,
};

/// Replay the run-length-coded code-length stream exactly as the decoder's
/// symbol loop would, and rebuild `out`. Also asserts the writer emitted no
/// item beyond the point where the decoder stops reading (`space` reaching 0).
fn replayCodeLengths(items: []const RleItem, alphabet_size: usize, out: []u8) ReadBackError!void {
    @memset(out, 0);
    var symbol: usize = 0;
    var prev_code_len: u32 = tables.initial_repeated_code_length;
    var repeat: u32 = 0;
    var repeat_code_len: u32 = 0;
    var space: i32 = 32768;
    var idx: usize = 0;
    while (symbol < alphabet_size and space > 0) {
        if (idx == items.len) return error.RanOut;
        const it = items[idx];
        idx += 1;
        const code_len: u32 = it.sym;
        if (code_len < 16) {
            if (it.nextra != 0) return error.WrongExtraWidth;
            repeat = 0;
            if (code_len != 0) {
                out[symbol] = @intCast(code_len);
                prev_code_len = code_len;
                space -= @as(i32, 32768) >> @intCast(code_len);
            }
            symbol += 1;
        } else {
            const extra_bits: u32 = if (code_len == 16) 2 else 3;
            if (it.nextra != extra_bits) return error.WrongExtraWidth;
            if (it.extra >= (@as(u32, 1) << @intCast(extra_bits))) return error.ExtraOutOfRange;
            const new_len: u32 = if (code_len == 16) prev_code_len else 0;
            if (repeat_code_len != new_len) {
                repeat = 0;
                repeat_code_len = new_len;
            }
            const old_repeat = repeat;
            if (repeat > 0) repeat = (repeat - 2) << @intCast(extra_bits);
            repeat += it.extra + 3;
            const actual = repeat - old_repeat;
            if (symbol + actual > alphabet_size) return error.Overflow;
            if (repeat_code_len != 0) {
                var j: u32 = 0;
                while (j < actual) : (j += 1) {
                    out[symbol] = @intCast(repeat_code_len);
                    symbol += 1;
                }
                space -= @as(i32, @intCast(actual)) << @intCast(15 - repeat_code_len);
            } else {
                symbol += actual;
            }
        }
    }
    if (space != 0) return error.Incomplete;
    if (idx != items.len) return error.TrailingItems;
}

/// Read a complex prefix code back out of a bit stream and return the per-symbol
/// code lengths — the bit-level counterpart of `writeComplexCode`.
fn readComplexCode(
    gpa: std.mem.Allocator,
    br: *BitReader,
    alphabet_size: usize,
    out: []u8,
) !void {
    if (try br.takeBits(2) != 0) return error.BadHskip;

    var cl_lengths = [_]u8{0} ** tables.code_length_codes;
    var space: i32 = 32;
    var num_codes: u32 = 0;
    for (tables.code_length_code_order) |idx| {
        const b4 = br.peekBits(4);
        const plen = tables.code_length_prefix_length[b4];
        _ = try br.takeBits(plen);
        const v = tables.code_length_prefix_value[b4];
        cl_lengths[idx] = v;
        if (v != 0) {
            space -= @as(i32, 32) >> @intCast(v);
            num_codes += 1;
            if (space <= 0) break;
        }
    }
    if (!(num_codes == 1 or space == 0)) return error.BadCodeLengthCode;

    var cl_table = try huffman.buildComplex(gpa, &cl_lengths);
    defer cl_table.deinit(gpa);

    var items: std.ArrayListUnmanaged(RleItem) = .empty;
    defer items.deinit(gpa);
    var symbol: usize = 0;
    var prev_code_len: u32 = tables.initial_repeated_code_length;
    var repeat: u32 = 0;
    var repeat_code_len: u32 = 0;
    var space2: i32 = 32768;
    while (symbol < alphabet_size and space2 > 0) {
        const code_len = try br.readSymbol(&cl_table);
        if (code_len < 16) {
            repeat = 0;
            try items.append(gpa, .{ .sym = @intCast(code_len), .extra = 0, .nextra = 0 });
            if (code_len != 0) {
                prev_code_len = code_len;
                space2 -= @as(i32, 32768) >> @intCast(code_len);
            }
            symbol += 1;
        } else {
            const extra_bits: u3 = if (code_len == 16) 2 else 3;
            const delta = try br.takeBits(extra_bits);
            try items.append(gpa, .{ .sym = @intCast(code_len), .extra = @intCast(delta), .nextra = extra_bits });
            const new_len: u32 = if (code_len == 16) prev_code_len else 0;
            if (repeat_code_len != new_len) {
                repeat = 0;
                repeat_code_len = new_len;
            }
            const old_repeat = repeat;
            if (repeat > 0) repeat = (repeat - 2) << extra_bits;
            repeat += delta + 3;
            const actual = repeat - old_repeat;
            if (symbol + actual > alphabet_size) return error.Overflow;
            if (repeat_code_len != 0) {
                space2 -= @as(i32, @intCast(actual)) << @intCast(15 - repeat_code_len);
                symbol += actual;
            } else {
                symbol += actual;
            }
        }
    }
    if (space2 != 0) return error.Incomplete;
    try replayCodeLengths(items.items, alphabet_size, out);
}

/// Read any prefix code — simple (3.4) or complex (3.5) — the way
/// `Decoder.readHuffmanCode` would, and return the table it builds.
fn readAnyCode(gpa: std.mem.Allocator, br: *BitReader, alphabet_size: u32) !huffman.Table {
    const kind = br.peekBits(2);
    if (kind == 1) {
        _ = try br.takeBits(2);
        const max_bits = huffman.symbolBits(alphabet_size - 1);
        const nsym_sel = try br.takeBits(2);
        const count = nsym_sel + 1;
        var vals: [4]u16 = undefined;
        for (0..count) |i| vals[i] = @intCast(try br.takeBits(max_bits));
        var num_symbols: u8 = @intCast(nsym_sel);
        if (nsym_sel == 3) num_symbols += @intCast(try br.takeBits(1));
        return huffman.buildSimple(gpa, num_symbols, vals[0..count]);
    }
    const lengths = try gpa.alloc(u8, alphabet_size);
    defer gpa.free(lengths);
    try readComplexCode(gpa, br, alphabet_size, lengths);
    return huffman.buildComplex(gpa, lengths);
}

// --- M1: the code-length prefix code ---------------------------------------

test "Effort: each level names its quality, fromQuality rounds up" {
    for (std.enums.values(Effort)) |e| try testing.expectEqual(e, Effort.fromQuality(e.quality()));
    const want = [12]Effort{ .q0, .q1, .q4, .q4, .q4, .q6, .q6, .q9, .q9, .q9, .q11, .q11 };
    for (want, 0..) |e, q| try testing.expectEqual(e, Effort.fromQuality(@intCast(q)));
    try testing.expectEqual(Effort.q11, Effort.fromQuality(99));
    try testing.expectEqual(Effort.q6, Effort.default);
    const opts: CompressOptions = .{};
    try testing.expectEqual(Effort.default, opts.effort);
}

test "canonicalCode: the decoder's table reads the same patterns" {
    var prng = std.Random.DefaultPrng.init(0xc0de);
    const r = prng.random();
    var counts: [tables.num_command_symbols]u32 = undefined;
    var lengths: [tables.num_command_symbols]u8 = undefined;
    for (0..300) |round| {
        const n: usize = 2 + r.uintLessThan(usize, counts.len - 1);
        for (counts[0..n]) |*c| c.* = if (r.uintLessThan(u8, 4) == 0) 0 else 1 + r.uintLessThan(u32, if (round % 2 == 0) 50 else 100_000);
        counts[0] = 1;
        counts[n - 1] = 1;
        _ = try assignLengths(testing.allocator, counts[0..n], tables.max_code_length, lengths[0..n]);
        var got = try canonicalCode(testing.allocator, lengths[0..n]);
        defer got.deinit(testing.allocator);
        var table = try huffman.buildComplex(testing.allocator, lengths[0..n]);
        defer table.deinit(testing.allocator);
        var want = try codeFromTable(testing.allocator, &table, @intCast(n));
        defer want.deinit(testing.allocator);
        try testing.expectEqualSlices(u8, want.len, got.len);
        try testing.expectEqualSlices(u16, want.bits, got.bits);
    }
    // An incomplete code is refused, as the table refuses it.
    try testing.expectError(error.EncoderInvariant, canonicalCode(testing.allocator, &.{ 1, 2, 0, 3 }));
}

test "DistRing keeps the decoder's last four distances in order" {
    var ring: DistRing = .{};
    ring.update(100, null);
    ring.update(200, null);
    try testing.expectEqual([4]u32{ 200, 100, 4, 11 }, ring.last);
    // Code 0 leaves the ring as it is; any other code pushes.
    ring.update(200, 0);
    try testing.expectEqual([4]u32{ 200, 100, 4, 11 }, ring.last);
    ring.update(101, 5);
    try testing.expectEqual([4]u32{ 101, 200, 100, 4 }, ring.last);
    // Every short code is reachable: the older three by index, and the
    // deltas around the second-last.
    try testing.expectEqual(@as(?u16, 0), ring.shortCode(101));
    try testing.expectEqual(@as(?u16, 1), ring.shortCode(200));
    try testing.expectEqual(@as(?u16, 2), ring.shortCode(100));
    try testing.expectEqual(@as(?u16, 3), ring.shortCode(4));
    try testing.expectEqual(@as(?u16, 5), ring.shortCode(102));
    try testing.expectEqual(@as(?u16, 10), ring.shortCode(199));
    try testing.expectEqual(@as(?u16, 15), ring.shortCode(203));
    try testing.expectEqual(@as(?u16, null), ring.shortCode(150));
}

test "cl_prefix is the exact inverse of the decoder's fixed prefix code" {
    // For every value, the bits we would write must be read back as that value
    // no matter what follows them: the decoder peeks a full 4 bits, so all 16
    // patterns whose low `len` bits match must decode identically.
    for (cl_prefix, 0..) |p, v| {
        try testing.expect(p.len >= 2 and p.len <= 4);
        var high: u32 = 0;
        while (high < 16) : (high += 1) {
            const b4 = (high << p.len | p.bits) & 0xf;
            if (b4 & ((@as(u32, 1) << p.len) - 1) != p.bits) continue;
            try testing.expectEqual(@as(u8, p.len), tables.code_length_prefix_length[b4]);
            try testing.expectEqual(@as(u8, @intCast(v)), tables.code_length_prefix_value[b4]);
        }
    }
}

test "repeat chains invert the decoder's repeat recurrence" {
    const gpa = testing.allocator;
    for ([2]u8{ tables.repeat_previous_code_length, tables.repeat_zero_code_length }) |sym| {
        const nextra: u3 = if (sym == 16) 2 else 3;
        var n: usize = 3;
        while (n <= 2000) : (n += 1) {
            var items: std.ArrayListUnmanaged(RleItem) = .empty;
            defer items.deinit(gpa);
            try emitRepeatChain(gpa, &items, sym, nextra, n);

            // Replay just the chain: the decoder accumulates `repeat` across
            // the whole chain and applies the delta each step.
            var total: u32 = 0;
            var repeat: u32 = 0;
            for (items.items) |it| {
                const old = repeat;
                if (repeat > 0) repeat = (repeat - 2) << nextra;
                repeat += it.extra + 3;
                total += repeat - old;
            }
            try testing.expectEqual(@as(u32, @intCast(n)), total);
        }
    }
}

fn expectRleRoundTrip(lengths: []const u8) !void {
    const gpa = testing.allocator;
    var items: std.ArrayListUnmanaged(RleItem) = .empty;
    defer items.deinit(gpa);
    try rleCodeLengths(gpa, lengths, &items);
    const back = try gpa.alloc(u8, lengths.len);
    defer gpa.free(back);
    try replayCodeLengths(items.items, lengths.len, back);
    try testing.expectEqualSlices(u8, lengths, back);
}

test "rle of code lengths replays to the same lengths" {
    // Two symbols, no repeats at all.
    try expectRleRoundTrip(&[_]u8{ 1, 1 });
    // A run short enough to stay literal (< 3 after the leading literal).
    try expectRleRoundTrip(&[_]u8{ 2, 2, 2, 2 });
    // A long run of one length: REPEAT_PREVIOUS chain.
    try expectRleRoundTrip(&([_]u8{3} ** 8));
    // Zeros between codes: REPEAT_ZERO chain, then a REPEAT_PREVIOUS chain.
    try expectRleRoundTrip(&([_]u8{ 1, 2 } ++ [_]u8{0} ** 30 ++ [_]u8{5} ** 8));
    // Two separate REPEAT_PREVIOUS chains for the same length, so the decoder's
    // `repeat_code_len` is already equal to the new one when the second starts.
    try expectRleRoundTrip(&([_]u8{1} ++ [_]u8{0} ** 30 ++ [_]u8{4} ** 4 ++ [_]u8{0} ** 20 ++ [_]u8{4} ** 4));
    // Trailing zeros must not be emitted at all.
    try expectRleRoundTrip(&([_]u8{ 1, 2, 2 } ++ [_]u8{0} ** 200));
    // A chain long enough to need several REPEAT codes.
    try expectRleRoundTrip(&([_]u8{1} ++ [_]u8{0} ** 700 ++ [_]u8{1}));
}

test "rle of code lengths replays to the same lengths (random complete codes)" {
    const gpa = testing.allocator;
    var seed: u64 = 0x5eed_b207;
    var iter: usize = 0;
    while (iter < 300) : (iter += 1) {
        const alphabet: usize = 2 + (@as(usize, @truncate(seed >> 13)) % 703);
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const counts = try gpa.alloc(u32, alphabet);
        defer gpa.free(counts);
        var used: usize = 0;
        for (counts) |*c| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            // Sparse and skewed: exercises long code lengths and long zero runs.
            const r: u32 = @truncate(seed >> 20);
            c.* = if (r % 3 == 0) 0 else (r % 4096) + 1;
            if (c.* != 0) used += 1;
        }
        if (used < 2) continue;
        const lengths = try gpa.alloc(u8, alphabet);
        defer gpa.free(lengths);
        _ = try assignLengths(gpa, counts, tables.max_code_length, lengths);
        try expectRleRoundTrip(lengths);
    }
}

test "complex prefix code survives a bit-level write/read round trip" {
    const gpa = testing.allocator;
    const cases = [_][]const u8{
        &[_]u8{ 1, 1 },
        &[_]u8{ 1, 2, 2 },
        &([_]u8{3} ** 8),
        &([_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15 }),
        &([_]u8{ 1, 2 } ++ [_]u8{0} ** 60 ++ [_]u8{5} ** 8),
        &([_]u8{1} ++ [_]u8{0} ** 60 ++ [_]u8{4} ** 4 ++ [_]u8{0} ** 20 ++ [_]u8{4} ** 4),
    };
    for (cases) |lengths| {
        var w = BitWriter{ .gpa = gpa };
        defer w.buf.deinit(gpa);
        try writeComplexCode(gpa, &w, lengths);
        try w.alignToByte();

        var br = BitReader.init(w.buf.items);
        const back = try gpa.alloc(u8, lengths.len);
        defer gpa.free(back);
        try readComplexCode(gpa, &br, lengths.len, back);
        try testing.expectEqualSlices(u8, lengths, back);
    }
}

// --- code construction ------------------------------------------------------

test "assignLengths yields a complete code within the limit" {
    const gpa = testing.allocator;
    var seed: u64 = 0xc0de_1234;
    var iter: usize = 0;
    while (iter < 200) : (iter += 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const alphabet: usize = 2 + (@as(usize, @truncate(seed >> 11)) % 703);
        const counts = try gpa.alloc(u32, alphabet);
        defer gpa.free(counts);
        var used: usize = 0;
        for (counts) |*c| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            const r: u32 = @truncate(seed >> 17);
            // Wildly skewed counts are what force the depth limit to bite.
            c.* = if (r % 5 == 0) 0 else (@as(u32, 1) << @intCast(r % 20)) + (r % 7);
            if (c.* != 0) used += 1;
        }
        if (used < 2) continue;
        const lengths = try gpa.alloc(u8, alphabet);
        defer gpa.free(lengths);
        const m = try assignLengths(gpa, counts, tables.max_code_length, lengths);
        try testing.expectEqual(used, m);

        var kraft: u64 = 0;
        for (lengths, counts) |l, c| {
            try testing.expect((l == 0) == (c == 0));
            if (l != 0) {
                try testing.expect(l <= tables.max_code_length);
                kraft += @as(u64, 1) << @intCast(tables.max_code_length - l);
            }
        }
        try testing.expectEqual(@as(u64, 1) << tables.max_code_length, kraft);
        // buildComplex enforces the same completeness the decoder demands.
        var t = try huffman.buildComplex(gpa, lengths);
        t.deinit(gpa);
    }
}

test "assignLengths honours the 5-bit limit of the code-length alphabet" {
    const gpa = testing.allocator;
    // Counts spread over powers of two: unlimited Huffman would go 17 deep.
    var counts: [tables.code_length_codes]u32 = undefined;
    for (&counts, 0..) |*c, i| c.* = @as(u32, 1) << @intCast(i);
    var lengths = [_]u8{0} ** tables.code_length_codes;
    _ = try assignLengths(gpa, &counts, 5, &lengths);
    for (lengths) |l| try testing.expect(l >= 1 and l <= 5);
    var t = try huffman.buildComplex(gpa, &lengths);
    t.deinit(gpa);
}

test "sortKeys: ascending, as a library sort, at every length up to an alphabet" {
    var seed: u64 = 0x5eed_0016;
    var keys: [tables.num_command_symbols + 100]u64 = undefined;
    var want: [keys.len]u64 = undefined;
    for (0..keys.len + 1) |n| {
        for (keys[0..n]) |*k| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            // Few distinct counts (ties broken by the symbol bits below),
            // as in a real histogram.
            k.* = (seed >> 60) << 32 | (seed >> 20 & 0xffff);
        }
        @memcpy(want[0..n], keys[0..n]);
        std.sort.pdq(u64, want[0..n], {}, std.sort.asc(u64));
        sortKeys(keys[0..n]);
        try testing.expectEqualSlices(u64, want[0..n], keys[0..n]);
    }
}

/// A histogram found by a search (2026-10-16) where a stride's count meets
/// `optimizeCountsForRle`'s streak bound exactly: `>=` and `>` part there.
const rle_kat_case4 = [256]u32{
    4,  2,  4,  3,  3,  2,  4,   3,   2,   3,   4,   2,   0,   1,   0,   0,   4,   1,   0,   0,   1,   0,   3,   3,   58,  58,  58,  58, 58,
    58, 58, 3,  4,  4,  4,  2,   3,   2,   4,   0,   3,   4,   1,   269, 270, 0,   0,   55,  59,  57,  53,  42,  40,  39,  40,  41,  42, 2,
    2,  1,  2,  2,  2,  2,  3,   1,   2,   1,   3,   0,   1,   2,   1,   1,   4,   2,   5,   0,   0,   0,   0,   0,   0,   1,   3,   3,  1,
    3,  1,  3,  3,  2,  3,  3,   1,   24,  22,  24,  22,  24,  23,  22,  3,   1,   1,   2,   2,   2,   1,   1,   3,   2,   2,   2,   0,  0,
    0,  0,  0,  0,  0,  0,  0,   0,   3,   0,   3,   6,   2,   2,   2,   3,   7,   4,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,
    0,  0,  2,  2,  0,  1,  1,   2,   1,   2,   2,   2,   1,   1,   0,   0,   3,   0,   0,   0,   0,   0,   0,   88,  87,  88,  89,  87, 87,
    87, 88, 88, 87, 89, 89, 331, 329, 331, 331, 330, 331, 327, 330, 329, 329, 3,   3,   2,   1,   0,   2,   0,   0,   2,   1,   3,   20, 18,
    21, 18, 19, 20, 21, 2,  2,   2,   2,   2,   3,   370, 368, 370, 370, 366, 368, 371, 277, 277, 278, 277, 276, 278, 277, 276, 278, 1,  3,
    2,  2,  3,  3,  3,  2,  1,   0,   1,   3,   1,   3,   4,   2,   0,   2,   5,   7,   1,   2,   0,   0,   0,   0,
};

/// `tools/c_oracle/rle_counts_kat.c`'s histogram `n`, from the same
/// generator.
fn rleKatCase(n: u32, buf: *[tables.num_command_symbols]u32) []u32 {
    var state: u64 = 0x9e3779b97f4a7c15 *% @as(u64, n + 1);
    const len: usize = if (n == 1) tables.num_command_symbols else 256;
    for (buf[0..len], 0..) |*c, i| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const r: u32 = @truncate(state >> 33);
        const k: u32 = @intCast(i);
        c.* = switch (n) {
            0 => if (r % 7 == 0) 0 else (r >> 7) % (1 + k * 37 % 50),
            1 => if (k % 24 < 8 or k >= 690) 0 else 1 + r % 3,
            2 => 1000 / (1 + k / 8) + r % 5,
            4 => rle_kat_case4[i],
            else => if (r % 11 == 0) 0 else 40 * (1 + k / 32) + r % 9,
        };
    }
    return buf[0..len];
}

test "optimizeCountsForRle: google/brotli's smoothing, count for count" {
    // SHA-256 of the counts (u32 little-endian) google/brotli 1.2.0's
    // `BrotliOptimizeHuffmanCountsForRle` leaves, from
    // `tools/c_oracle/rle_counts_kat.c` (2026-10-16). It changes 30, 291,
    // 207 and 153 of the first four; the fifth parts `>=` from `>` at the
    // streak bound. (The initial `+ 420` cannot be told from `+ 400` by any
    // input: `256·c − ⌊256·S/3⌋` is ⌈256k/3⌉, never in the 20 between.)
    const want = [_]*const [64]u8{
        "a27023958f2e960b48af7228061e217d3c098bca2366c1c743ebef6c37bde1fc",
        "7e1c914ecb693000e644a46f35342f1a877d4c97ae141da5eb5c46f73aa9bd49",
        "d29f0732a08c78285bf5fbf54fe280cb737d7e6d9eba587ef681a22cf8228839",
        "aff1a49d9e14736ceb63c40eba058e9c560f1cd0f6f6d35cc2f2f3f3a6012eb2",
        "b17db1e052f164830654aa172ea2c5808c1d6b0dc9d965b7866c161306e9e38e",
    };
    for (want, 0..) |hex, n| {
        var buf: [tables.num_command_symbols]u32 = undefined;
        const counts = rleKatCase(@intCast(n), &buf);
        optimizeCountsForRle(counts);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (counts) |c| h.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, c)));
        var digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&digest, hex);
        try testing.expectEqualSlices(u8, &digest, &h.finalResult());
    }
}

test "optimizeCountsForRle: a used symbol stays used; under 16 used, nothing changes" {
    var seed: u64 = 0x0071_e5;
    for (0..300) |iter| {
        var counts: [256]u32 = undefined;
        // Up to 40 used symbols, so both sides of the 16 threshold.
        const dens: u64 = 1 + iter % 40;
        for (&counts) |*c| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            c.* = if ((seed >> 40) % 256 < dens * 6) @intCast(1 + (seed >> 20) % 300) else 0;
        }
        const before = counts;
        optimizeCountsForRle(&counts);
        var used: usize = 0;
        for (before, counts) |b, a| {
            used += @intFromBool(b != 0);
            if (b != 0) try testing.expect(a != 0);
        }
        if (used < 16) try testing.expectEqualSlices(u32, &before, &counts);
    }
}

test "codeFromTable patterns decode back to their own symbols" {
    const gpa = testing.allocator;
    // Complex code: every symbol's written bits must read back as that symbol
    // through the decoder's own BitReader + table.
    const lengths = [_]u8{ 1, 3, 3, 4, 5, 5, 5, 5, 4 };
    var table = try huffman.buildComplex(gpa, &lengths);
    defer table.deinit(gpa);
    var code = try codeFromTable(gpa, &table, lengths.len);
    defer code.deinit(gpa);

    for (lengths, 0..) |l, sym| {
        try testing.expectEqual(l, code.len[sym]);
        var w = BitWriter{ .gpa = gpa };
        defer w.buf.deinit(gpa);
        try code.emit(&w, sym);
        try w.writeBits(0xffff, 16); // trailing bits must not change the symbol
        try w.alignToByte();
        var br = BitReader.init(w.buf.items);
        try testing.expectEqual(@as(u16, @intCast(sym)), try br.readSymbol(&table));
    }
}

test "codeFromTable handles every simple-code shape" {
    const gpa = testing.allocator;
    const shapes = [_]struct { n: u8, vals: []const u16 }{
        .{ .n = 0, .vals = &.{7} },
        .{ .n = 1, .vals = &.{ 3, 9 } },
        .{ .n = 2, .vals = &.{ 1, 4, 8 } },
        .{ .n = 3, .vals = &.{ 0, 2, 5, 6 } },
        .{ .n = 4, .vals = &.{ 0, 2, 5, 6 } },
    };
    for (shapes) |s| {
        var table = try huffman.buildSimple(gpa, s.n, s.vals);
        defer table.deinit(gpa);
        var code = try codeFromTable(gpa, &table, 16);
        defer code.deinit(gpa);
        for (s.vals) |sym| {
            var w = BitWriter{ .gpa = gpa };
            defer w.buf.deinit(gpa);
            try code.emit(&w, sym);
            try w.writeBits(0xffff, 16);
            try w.alignToByte();
            var br = BitReader.init(w.buf.items);
            try testing.expectEqual(sym, try br.readSymbol(&table));
        }
    }
}

// --- length / distance code tables -----------------------------------------

test "command length codes reproduce every insert and copy length" {
    // Insert lengths tile [0, ...] and copy lengths tile [2, ...] contiguously;
    // the chosen code + extra bits must reconstruct the length exactly.
    var len: u32 = 0;
    while (len < 40000) : (len += 1) {
        const ic = lengthCode(&cmd_tables.insert_off, &cmd_tables.insert_nbits, len) orelse
            return error.NoInsertCode;
        try testing.expectEqual(len, cmd_tables.insert_off[ic.code] + ic.extra);
        try testing.expect(ic.extra < @as(u64, 1) << ic.nbits);

        const cl = @max(len, 2);
        const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, cl) orelse
            return error.NoCopyCode;
        try testing.expectEqual(cl, cmd_tables.copy_off[cc.code] + cc.extra);
    }
    // Copy length 0 and 1 are not representable — the format's minimum is 2.
    try testing.expect(lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, 0) == null);
    try testing.expect(lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, 1) == null);
}

test "command symbols agree with the decoder's own cmd_lut" {
    for (cmd_tables.sym, 0..) |row, ic| {
        for (row, 0..) |sym, cc| {
            const e = tables.cmd_lut[sym];
            try testing.expectEqual(cmd_tables.insert_off[ic], e.insert_len_offset);
            try testing.expectEqual(cmd_tables.copy_off[cc], e.copy_len_offset);
            try testing.expectEqual(cmd_tables.insert_nbits[ic], @as(u5, @intCast(e.insert_len_extra_bits)));
            try testing.expectEqual(cmd_tables.copy_nbits[cc], @as(u5, @intCast(e.copy_len_extra_bits)));
            // Every symbol this encoder emits must read an explicit distance.
            try testing.expectEqual(@as(i8, -1), e.distance_code);
        }
    }
}

test "distance codes reproduce every distance without gaps" {
    // Ranges must tile [1, ...]: any hole would make some match distance
    // unencodable, and any overlap-with-shift would decode to a different one.
    var d: u32 = 1;
    while (d < 200000) : (d += 1) {
        const c = distanceCode(d, dist_alphabet_size) orelse return error.NoDistanceCode;
        try testing.expect(c.sym >= tables.num_distance_short_codes);
        try testing.expect(c.sym < dist_alphabet_size);
        try testing.expectEqual(d, dist_lut[c.sym].offset + c.extra);
        try testing.expect(c.extra < @as(u64, 1) << c.nbits);
    }
    // Distance 0 is the "unused" slot in the alphabet, never a real distance.
    try testing.expect(distanceCode(0, dist_alphabet_size) == null);
}

// --- whole-code write/read round trip, every shape --------------------------

fn expectCodeRoundTrip(counts: []const u32, alphabet_size: u32) !void {
    const gpa = testing.allocator;
    var w = BitWriter{ .gpa = gpa };
    defer w.buf.deinit(gpa);

    var code = try buildAndWriteCode(gpa, &w, counts, alphabet_size);
    defer code.deinit(gpa);

    var used: std.ArrayListUnmanaged(u16) = .empty;
    defer used.deinit(gpa);
    for (counts, 0..) |c, s| {
        if (c != 0) try used.append(gpa, @intCast(s));
    }
    for (used.items) |sym| try code.emit(&w, sym);
    try w.writeBits(0xffff, 16); // the reader must stop on its own
    try w.alignToByte();

    var br = BitReader.init(w.buf.items);
    var table = try readAnyCode(gpa, &br, alphabet_size);
    defer table.deinit(gpa);
    for (used.items) |sym| try testing.expectEqual(sym, try br.readSymbol(&table));
}

test "prefix code header + symbols round trip for 1..N used symbols" {
    var counts = [_]u32{0} ** tables.num_literal_symbols;

    // One symbol: only a simple code can express this at all.
    counts[65] = 100;
    try expectCodeRoundTrip(&counts, tables.num_literal_symbols);
    // Two, three, four symbols: the simple-code shapes.
    counts[7] = 40;
    try expectCodeRoundTrip(&counts, tables.num_literal_symbols);
    counts[200] = 5;
    try expectCodeRoundTrip(&counts, tables.num_literal_symbols);
    counts[3] = 1;
    try expectCodeRoundTrip(&counts, tables.num_literal_symbols);
    // Four symbols, flat counts: the other 4-symbol tree shape.
    counts[65] = 10;
    counts[7] = 10;
    counts[200] = 10;
    counts[3] = 10;
    try expectCodeRoundTrip(&counts, tables.num_literal_symbols);
    // Five symbols: crosses over into a complex code.
    counts[128] = 3;
    try expectCodeRoundTrip(&counts, tables.num_literal_symbols);

    // Dense and skewed.
    var dense = [_]u32{0} ** tables.num_literal_symbols;
    for (&dense, 0..) |*c, i| c.* = @intCast(1 + (i * i) % 997);
    try expectCodeRoundTrip(&dense, tables.num_literal_symbols);

    // The command and distance alphabets, whose symbol widths differ.
    var cmds = [_]u32{0} ** tables.num_command_symbols;
    cmds[0] = 1;
    cmds[703] = 5;
    cmds[128] = 9;
    try expectCodeRoundTrip(&cmds, tables.num_command_symbols);
    var dists = [_]u32{0} ** dist_alphabet_size;
    dists[16] = 7;
    try expectCodeRoundTrip(&dists, dist_alphabet_size);
}

test "compressInto: the stream compressWith gives, in exactly its length; a byte less does not fit" {
    const corpus = @import("interop_corpus.zig");
    const gpa = testing.allocator;
    for (corpus.shapes) |shape| {
        const input = try corpus.build(gpa, shape);
        defer gpa.free(input);
        if (input.len > 300_000) continue; // (the 1 MiB block shapes: slow, add nothing here)
        inline for (.{ Effort.q0, Effort.q1, .q4, .q6, .q9 }) |effort| {
            const opts: CompressOptions = .{ .effort = effort };
            const want = try compressWith(gpa, input, opts);
            defer gpa.free(want);
            const bound = maxCompressedSize(input.len, opts);
            try testing.expect(want.len <= bound);
            const buf = try gpa.alloc(u8, bound);
            defer gpa.free(buf);
            errdefer std.debug.print("compressInto: shape {s}, effort {s}\n", .{ shape.name, @tagName(effort) });
            try testing.expectEqualSlices(u8, want, try compressInto(gpa, buf, input, opts));
            try testing.expectEqualSlices(u8, want, try compressInto(gpa, buf[0..want.len], input, opts));
            try testing.expectError(error.OutputTooLarge, compressInto(gpa, buf[0 .. want.len - 1], input, opts));
        }
    }
}

test "maxCompressedSize is reached by incompressible input, whatever the blocks and window" {
    const gpa = testing.allocator;
    const input = try gpa.alloc(u8, 200_000);
    defer gpa.free(input);
    var prng: std.Random.DefaultPrng = .init(0x3a5);
    prng.random().bytes(input);
    for ([_]usize{ 0, 1, 17, 65_520, 65_521, 200_000 }) |n| {
        for ([_]?u5{ null, 10, 16, 17, 22 }) |wbits| for ([_]usize{ 1 << 20, 4096, 65_536 }) |bs| {
            const opts: CompressOptions = .{ .effort = .q4, .window_bits = wbits, .block_size = bs };
            const got = try compressWith(gpa, input[0..n], opts);
            defer gpa.free(got);
            try testing.expectEqual(maxCompressedSize(n, opts), got.len);
        };
    }
}

test "large window: a copy from 17 MiB back, the RFC 9841 header, refused unasked" {
    const gpa = testing.allocator;
    const decoder = @import("decoder.zig");
    const block = 8 * 1024;
    const gap = 17 << 20;
    const input = try gpa.alloc(u8, 2 * block + gap);
    defer gpa.free(input);
    var prng: std.Random.DefaultPrng = .init(0x1a5e);
    prng.random().bytes(input[0..block]);
    @memset(input[block..][0..gap], 0);
    @memcpy(input[block + gap ..], input[0..block]);
    for ([_]u5{ 25, 30 }) |wbits| {
        const opts: CompressOptions = .{ .effort = .q4, .window_bits = wbits };
        const out = try compressWith(gpa, input, opts);
        defer gpa.free(out);
        // One copy of the random block, not two.
        try testing.expect(out.len < block + block / 2);
        try testing.expect(out.len <= maxCompressedSize(input.len, opts));
        try testing.expectError(error.InvalidWindowBits, decoder.decompress(gpa, out, .{ .max_output = 1 << 26 }));
        const back = try decoder.decompress(gpa, out, .{ .large_window = true, .max_output = 1 << 26 });
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, input, back);
    }
    // A 24-bit window cannot reach it: both blocks stay.
    const near = try compressWith(gpa, input, .{ .effort = .q4, .window_bits = 24 });
    defer gpa.free(near);
    try testing.expect(near.len > 2 * block);
}

// --- `.q11`: shortest-path parse and static-dictionary words -----------------

fn expectMaxRoundTrip(input: []const u8, opts: CompressOptions, dopts: @import("decoder.zig").Options) ![]u8 {
    const gpa = testing.allocator;
    var o = opts;
    o.effort = .q11;
    const out = try compressWith(gpa, input, o);
    errdefer gpa.free(out);
    const back = try @import("decoder.zig").decompress(gpa, out, dopts);
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
    return out;
}

test "max: round trip across windows and block sizes, and smaller than best" {
    const gpa = testing.allocator;
    const alice = @embedFile("testdata/alice29.txt")[0..60_000];
    const best = try compressWith(gpa, alice, .{ .effort = .q9 });
    defer gpa.free(best);
    for ([_]CompressOptions{ .{}, .{ .window_bits = 16 }, .{ .window_bits = 12 }, .{ .block_size = 7_000 } }) |o| {
        const out = try expectMaxRoundTrip(alice, o, .{});
        defer gpa.free(out);
        if (o.window_bits == null and o.block_size == CompressOptions.default_block_size) try testing.expect(out.len < best.len);
    }
}

test "max: dictionary words with their transforms are used" {
    // Words of the static dictionary, spaced, cut, capitalised and in capitals:
    // without dictionary references this stays near its size as `.q9`.
    const text = "international organization government university information. " ++
        "International Organization Government University Information, " ++
        "INTERNATIONAL ORGANIZATION GOVERNMENT UNIVERSITY INFORMATION; " ++
        "the international organization of the government of the university\n" ++
        "tomorrow yesterday however sometimes everything something nothing";
    const gpa = testing.allocator;
    const out = try expectMaxRoundTrip(text, .{}, .{});
    defer gpa.free(out);
    const best = try compressWith(gpa, text, .{ .effort = .q9 });
    defer gpa.free(best);
    try testing.expect(out.len + 40 < best.len);
}

test "max: a prefix dictionary, a large window and a window the output has not filled" {
    const gpa = testing.allocator;
    const alice = @embedFile("testdata/alice29.txt");
    const dict = alice[0..20_000];
    const out = try expectMaxRoundTrip(alice[10_000..50_000], .{ .dictionary = dict, .window_bits = 18 }, .{ .dictionary = dict });
    gpa.free(out);
    const big = try expectMaxRoundTrip(alice[0..30_000], .{ .window_bits = 26 }, .{ .large_window = true });
    gpa.free(big);
}

test "max: every shape the encoder is checked on" {
    const gpa = testing.allocator;
    var rng = std.Random.DefaultPrng.init(0x6d61_7831);
    const r = rng.random();
    for (0..40) |_| {
        const n = r.uintLessThan(usize, 3000);
        const alphabet = 1 + r.uintLessThan(usize, 256);
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        for (data) |*b| b.* = @intCast(r.uintLessThan(usize, alphabet));
        // Some repeats, some words.
        if (n > 200) @memcpy(data[n / 2 ..][0..100], data[10..][0..100]);
        const out = try expectMaxRoundTrip(data, .{}, .{});
        gpa.free(out);
    }
    for ([_][]const u8{ "", "a", "the", " the the the ", "\x00" ** 70_000, "abc" ** 40_000 }) |d| {
        const out = try expectMaxRoundTrip(d, .{}, .{});
        gpa.free(out);
    }
}

test "max: a dictionary word that would decode to other bytes is refused (block stored)" {
    // "time" is word 1 of length 4 (RFC 7932 App. A: the list starts
    // "timedownlifeleftback…"): identity at max_distance + 2.
    const env: BlockEnv = .{ .max_backward = (1 << 16) - 16 };
    const n = 4;
    const idx = std.mem.indexOf(u8, dictionary.data[dictionary.offsets_by_length[n]..][0 .. n << 10], "time").? / n;
    const pos = 100;
    const good: Cmd = .{ .insert_len = 0, .copy_len = n, .dist = @intCast(pos + 1 + idx), .out_len = n };
    try checkWord(good, pos, env, "time");
    try testing.expectError(error.EncoderInvariant, checkWord(good, pos, env, "tame"));
    var off = good;
    off.dist += 1;
    try testing.expectError(error.EncoderInvariant, checkWord(off, pos, env, "time"));
    var short = good;
    short.out_len = 3;
    try testing.expectError(error.EncoderInvariant, checkWord(short, pos, env, "tim"));
    // At or below max_distance it is a copy, not a word.
    var near = good;
    near.dist = pos;
    try testing.expectError(error.EncoderInvariant, checkWord(near, pos, env, "time"));
    // With a prefix dictionary of 10 bytes, word ids start 10 further: the
    // same distance now names the word before, and 10 more names "time".
    const px: BlockEnv = .{ .max_backward = (1 << 16) - 16, .reach = 10 };
    try testing.expectError(error.EncoderInvariant, checkWord(good, pos, px, "time"));
    var past = good;
    past.dist += 10;
    try checkWord(past, pos, px, "time");
}

test "q9: static-dictionary words where no copy is found, past a prefix dictionary too" {
    const gpa = testing.allocator;
    const text = "international organization government university information. " ++
        "tomorrow yesterday however sometimes everything something nothing; " ++
        "the development of the environment and the management of the community";
    const max_dist = (1 << 22) - 16;
    // A dictionary that shares no five bytes with the text: the words stay,
    // counted past it.
    const dict = "0123456789" ** 7;
    var pd = try PreparedDictionary.init(gpa, dict);
    defer pd.deinit(gpa);
    for ([_]u2{ 0, 1, 2 }) |case| {
        var m = try Matcher.init(gpa, simd_depth, Effort.q6.slotsLog(text.len));
        defer m.deinit(gpa);
        m.setData(text);
        var cmds: std.ArrayListUnmanaged(Cmd) = .empty;
        defer cmds.deinit(gpa);
        switch (case) {
            0 => try buildCommands(4, std.math.maxInt(usize), false, false, false, true, gpa, &m, 0, text.len, max_dist, &cmds),
            1 => try buildCommands(4, std.math.maxInt(usize), false, false, false, false, gpa, &m, 0, text.len, max_dist, &cmds),
            else => {
                m.dict = .{ .pd = &pd };
                m.dict_len = dict.len;
                try buildCommands(4, std.math.maxInt(usize), true, false, false, true, gpa, &m, 0, text.len, max_dist, &cmds);
            },
        }
        const reach: usize = if (case == 2) dict.len else 0;
        var n_words: usize = 0;
        var pos: usize = 0;
        for (cmds.items) |c| {
            pos += c.insert_len;
            if (c.out_len != 0) {
                n_words += 1;
                // Each decodes to the bytes it stands for.
                try checkWord(c, pos, .{ .max_backward = max_dist, .reach = reach }, text[pos..][0..c.out_len]);
            }
            pos += c.produced();
        }
        try testing.expectEqual(text.len, pos);
        if (case != 1) try testing.expect(n_words >= 10) else try testing.expectEqual(0, n_words);
    }
    for ([_]Effort{ .q6, .q9 }) |effort| {
        const out = try compressWith(gpa, text, .{ .effort = effort });
        defer gpa.free(out);
        const back = try @import("decoder.zig").decompress(gpa, out, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, text, back);
    }
}

test "q9: dictionary lookups stop on data that never finds a word" {
    const gpa = testing.allocator;
    const data = try gpa.alloc(u8, 1 << 16);
    defer gpa.free(data);
    var rng = std.Random.DefaultPrng.init(0x7231_3500);
    rng.random().bytes(data);
    var m = try Matcher.init(gpa, simd_depth, Effort.q6.slotsLog(data.len));
    defer m.deinit(gpa);
    m.setData(data);
    var cmds: std.ArrayListUnmanaged(Cmd) = .empty;
    defer cmds.deinit(gpa);
    try buildCommands(4, std.math.maxInt(usize), false, false, false, true, gpa, &m, 0, data.len, (1 << 22) - 16, &cmds);
    // Two buckets a lookup; it stops once fewer than 1 in 128 found a word.
    try testing.expect(m.dict_lookups <= 128 * (m.dict_matches + 1) + 2);
    try testing.expect(m.dict_lookups < data.len / 64);
}

test "q9: a dictionary word whose distance no code reaches is not taken" {
    // A word's distance is the output so far plus its index (RFC 7932
    // §8): past `max_code_distance` no distance code names it, whatever its
    // gain.
    const gpa = testing.allocator;
    var found = false;
    for ([_][]const u8{ "information ", "between the ", "language ", "following " }) |text| {
        var m = try Matcher.init(gpa, simd_depth, Effort.q6.slotsLog(text.len));
        defer m.deinit(gpa);
        m.setData(text);
        const near = m.findWord(0, 1000, text.len) orelse continue;
        found = true;
        try testing.expect(near.dist <= max_code_distance);
        try testing.expect(m.findWord(0, max_code_distance, text.len) == null);
    }
    try testing.expect(found);
}

/// NBLTYPESL of the stream's first meta-block (a compressed one).
fn firstLiteralBlockTypes(stream: []const u8) !u32 {
    var br = BitReader.init(stream);
    // WBITS (RFC 7932 §9.1), not a large window.
    if (try br.takeBits(1) == 1) {
        if (try br.takeBits(3) == 0) _ = try br.takeBits(3);
    }
    const is_last = try br.takeBits(1);
    if (is_last == 1) try testing.expectEqual(@as(u32, 0), try br.takeBits(1));
    const nibbles = 4 + try br.takeBits(2);
    try testing.expect(nibbles <= 6);
    _ = try br.takeBits(nibbles * 4);
    if (is_last == 0) try testing.expectEqual(@as(u32, 0), try br.takeBits(1));
    // VarLenUint8 + 1.
    if (try br.takeBits(1) == 0) return 1;
    const n = try br.takeBits(3);
    const v: u32 = if (n == 0) 1 else (@as(u32, 1) << @intCast(n)) + try br.takeBits(n);
    return v + 1;
}

test "block types: .q6, .q9 and .q11 split a sectioned binary input, .q4 does not" {
    const gpa = testing.allocator;
    const corpus = @import("interop_corpus.zig");
    const input = try corpus.fontLike(gpa, 60_000, 7);
    defer gpa.free(input);
    for ([_]Effort{ .q4, .q6, .q9, .q11 }) |effort| {
        const out = try compressWith(gpa, input, .{ .effort = effort });
        defer gpa.free(out);
        const back = try @import("decoder.zig").decompress(gpa, out, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, input, back);
        const nbl = try firstLiteralBlockTypes(out);
        if (effort == .q4) try testing.expectEqual(@as(u32, 1), nbl) else try testing.expect(nbl >= 2);
    }
}

test "q0: whether the next bytes continue the meta-block (google ShouldMergeBlock)" {
    // 128 samples (every 43rd byte), all one symbol of code length d: the
    // cost bound is 128 * (7 + 0.5) + 200 against 128 * (d + 7), so
    // 2 bits continue it (8 to spare) and 3 do not.
    var bytes: [128 * 43]u8 = @splat('x');
    var i: usize = 0;
    while (i < bytes.len) : (i += 43) bytes[i] = 'a';
    var depth: [tables.num_literal_symbols]u8 = @splat(9);
    depth['a'] = 2;
    try testing.expect(q0ShouldMerge(&bytes, &depth));
    depth['a'] = 3;
    try testing.expect(!q0ShouldMerge(&bytes, &depth));
}

test "a block without literals under several literal contexts is compressed, not stored" {
    // The second block copies the first whole: no literals. On Cyrillic
    // text `.q6`/`.q9` model literals with two or three static contexts, and
    // pricing the one-code alternative over no literals failed the block
    // (`EncoderInvariant`), which was then stored: 8 KiB of raw bytes.
    const gpa = testing.allocator;
    const decoder = @import("decoder.zig");
    const letters = "абвгдежзийклмнопрстуфхцчшщыэюя";
    var a: [8192]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x0b10c);
    var k: usize = 0;
    while (k + 2 <= a.len) {
        if (prng.random().uintLessThan(u8, 6) == 0) {
            a[k] = ' ';
            k += 1;
        } else {
            const i = 2 * prng.random().uintLessThan(usize, letters.len / 2);
            @memcpy(a[k..][0..2], letters[i..][0..2]);
            k += 2;
        }
    }
    if (k < a.len) a[k] = ' ';
    try testing.expect(greedy_split.chooseStaticContexts(&a, 9, 0).n >= 2);
    const input = try gpa.alloc(u8, 2 * a.len);
    defer gpa.free(input);
    @memcpy(input[0..a.len], &a);
    @memcpy(input[a.len..], &a);
    for ([_]Effort{ .q6, .q9 }) |effort| {
        const one = try compressWith(gpa, &a, .{ .effort = effort, .block_size = a.len });
        defer gpa.free(one);
        const two = try compressWith(gpa, input, .{ .effort = effort, .block_size = a.len });
        defer gpa.free(two);
        // The copy block costs a few bytes.
        try testing.expect(two.len < one.len + 64);
        const back = try decoder.decompress(gpa, two, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, input, back);
    }
}

test "chooseDistParams: NDIRECT's search halves where it starts for each NPOSTFIX (google's order)" {
    // Distances that are multiples of eight: NPOSTFIX 3 pays, and the
    // search for its NDIRECT starts at half the last NPOSTFIX's best (google
    // `BrotliBuildMetaBlock`). Started from that best itself it ends at 120.
    var cmds: [200]Cmd = undefined;
    for (&cmds, 0..) |*c, k| c.* = .{ .insert_len = 1, .copy_len = @intCast(4 + k % 8), .dist = @intCast(8 * (1 + (k * 2654435761) % 4000)) };
    const p = chooseDistParams(&cmds, .{});
    try testing.expectEqual(@as(u2, 3), p.npostfix);
    try testing.expectEqual(@as(u8, 72), p.ndirect);
    try testing.expect(distParamsCost(&cmds, .{}, p).? < distParamsCost(&cmds, .{}, .{}).?);
}

test "MinCopyLen: past every reached end, a bit more for each copy length bucket" {
    // All ends already reached at no cost: the walk goes one past the last
    // node (as google's `pos + len <= num_bytes`), adding a bit at lengths
    // 10, 14, 22 and 38 (`ComputeMinimumCopyLength`'s buckets of 4, 8, 16,
    // 32).
    var nodes: [41]OptNode = undefined;
    for (&nodes) |*nd| nd.* = .{ .cost = 0, .from = 0, .len = 0, .dist = 0, .ins = 0 };
    var w: MinCopyLen = .{};
    try testing.expectEqual(@as(u32, 41), w.at(&nodes, 0, 0));
    try testing.expectEqual(@as(f32, 4), w.added);
    // An end that costs more than the start plus what was added stops it,
    // and the walk resumes there for the next start.
    for (nodes[12..]) |*nd| nd.cost = 2;
    var v: MinCopyLen = .{};
    try testing.expectEqual(@as(u32, 12), v.at(&nodes, 0, 0.5));
    try testing.expectEqual(@as(u32, 41), v.at(&nodes, 0, 1.5));
}

test "relaxRingHits: a length an earlier short code reached is not tried at a later one (google best_len)" {
    // Codes 0 and 1 both copy 330 bytes (taken whole, >= max_take_len);
    // code 1 is priced far below code 0, but google tries only lengths past
    // what an earlier code reached, so 330 is code 0's. Code 2 reaches 340.
    const gpa = testing.allocator;
    const costs = try gpa.create(OptCosts);
    defer gpa.destroy(costs);
    @memset(&costs.cmd, 1);
    for (&costs.dist) |*row| {
        @memset(row, 1);
        row[0] = 20;
        row[1] = 0;
    }
    var nodes: [400]OptNode = undefined;
    for (&nodes) |*nd| nd.* = .{ .cost = std.math.inf(f32), .from = 0, .len = 0, .dist = 0, .ins = 0 };
    nodes[0].cost = 0;
    const ic = lengthCode(&cmd_tables.insert_off, &cmd_tables.insert_nbits, 0).?;
    const src: OptSrc = .{ .cost = 0, .ins = 0, .ring = .{ 5, 7, 11, 13 } };
    const hits = [_]RingHit{ .{ .code = 0, .d = 5, .l = 330 }, .{ .code = 1, .d = 7, .l = 330 }, .{ .code = 2, .d = 11, .l = 340 } };
    try testing.expectEqual(@as(u32, 340), relaxRingHits(&nodes, costs, src, ic, 0, &hits, 2, .{ .n = dist_alphabet_size }));
    try testing.expectEqual(@as(u32, 5), nodes[330].dist);
    try testing.expectEqual(@as(u32, 11), nodes[340].dist);
    // Taken whole: nothing shorter was relaxed.
    try testing.expectEqual(std.math.inf(f32), nodes[329].cost);
}

test "Compressor: compressWith's bytes, call after call, whatever came before" {
    const gpa = testing.allocator;
    const alice = @embedFile("testdata/alice29.txt");
    var noise: [9000]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x16);
    prng.random().bytes(&noise);
    const inputs = [_][]const u8{ alice[0..100], alice[0..5000], &noise, alice, alice[1000..70_000], "" };
    var pd = try PreparedDictionary.init(gpa, alice[60_000..90_000]);
    defer pd.deinit(gpa);
    var c: Compressor = .init(gpa);
    defer c.deinit();
    // Big after small after big, the effort switching under it, a
    // dictionary on some calls, a buffer too small on some.
    for (0..3) |round| for ([_]Effort{ .q0, .q1, .q4, .q6, .q9, .q11 }) |e| for (inputs, 0..) |in, k| {
        if (e == .q11 and in.len > 70_000) continue; // (slow; `.q9` has its table)
        const dict = (k + round) % 3 == 0;
        const opts: CompressOptions = .{ .effort = e, .prepared_dictionary = if (dict) &pd else null };
        const want = try compressWith(gpa, in, opts);
        defer gpa.free(want);
        if ((k + round) % 4 == 1 and want.len > 1) {
            var small: [64 * 1024]u8 = undefined;
            const n = @min(want.len - 1, small.len);
            try testing.expectError(error.OutputTooLarge, c.compressInto(small[0..n], in, opts));
            const into = try gpa.alloc(u8, want.len);
            defer gpa.free(into);
            try testing.expectEqualSlices(u8, want, try c.compressInto(into, in, opts));
        }
        const got = try c.compress(in, opts);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, want, got);
    };
}

test "Compressor: tables kept while big enough, given back after long being three times too big" {
    const gpa = testing.allocator;
    const alice = @embedFile("testdata/alice29.txt");
    var c: Compressor = .init(gpa);
    defer c.deinit();
    gpa.free(try c.compress(alice, .{}));
    const big = c.core.?.table_mem.len;
    gpa.free(try c.compress(alice[0..2000], .{}));
    const kept = c.core.?.table_mem;
    try testing.expectEqual(big, kept.len);
    try testing.expect(Core.tableLen(.q6, .deep, 2000) * 3 < big);
    for (0..127) |_| gpa.free(try c.compress(alice[0..2000], .{}));
    try testing.expectEqual(kept.ptr, c.core.?.table_mem.ptr);
    gpa.free(try c.compress(alice[0..2000], .{}));
    try testing.expectEqual(Core.tableLen(.q6, .deep, 2000), c.core.?.table_mem.len);
    // A bigger input than the tables: made anew, the bytes as ever.
    const out = try c.compress(alice, .{ .effort = .q9 });
    defer gpa.free(out);
    const want = try compressWith(gpa, alice, .{ .effort = .q9 });
    defer gpa.free(want);
    try testing.expectEqualSlices(u8, want, out);
}

test "a prepared dictionary gives the raw dictionary's bytes, and is searched from .q4" {
    const gpa = testing.allocator;
    const alice = @embedFile("testdata/alice29.txt");
    const dict = alice[0..40_000];
    const input = alice[30_000..60_000];
    var pd = try PreparedDictionary.init(gpa, dict);
    defer pd.deinit(gpa);
    inline for (.{ Effort.q0, .q1, .q4, .q6, .q9, .q11 }) |e| {
        const raw = try compressWith(gpa, input, .{ .effort = e, .dictionary = dict });
        defer gpa.free(raw);
        const prep = try compressWith(gpa, input, .{ .effort = e, .prepared_dictionary = &pd });
        defer gpa.free(prep);
        try testing.expectEqualSlices(u8, raw, prep);
        const plain = try compressWith(gpa, input, .{ .effort = e });
        defer gpa.free(plain);
        // The input starts with the dictionary's last 10 000 bytes (about
        // 3.5 KB compressed alone).
        if (@as(Effort, e).searchesDictionary()) try testing.expect(prep.len + 2000 < plain.len) else try testing.expectEqualSlices(u8, plain, prep);
        const back = try @import("decoder.zig").decompress(gpa, prep, .{ .dictionary = dict });
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, input, back);
    }
}

test "prefix dictionaries of every shape: raw and prepared agree, the stream decodes" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x9841);
    const r = prng.random();
    const alice = @embedFile("testdata/alice29.txt");
    for (0..60) |round| {
        // A dictionary of 0..20 000 bytes (text, noise or a run), an input
        // of its pieces, noise and runs, cut anywhere — copies that end at
        // the dictionary's end, ring distances into it, a window smaller
        // than it.
        const dlen = switch (round % 4) {
            0 => r.uintLessThan(usize, 16),
            1 => r.uintLessThan(usize, 300),
            else => r.uintLessThan(usize, 20_000),
        };
        const dict = try gpa.alloc(u8, dlen);
        defer gpa.free(dict);
        switch (round % 3) {
            0 => {
                const at = r.uintLessThan(usize, alice.len - dlen);
                @memcpy(dict, alice[at..][0..dlen]);
            },
            1 => r.bytes(dict),
            else => @memset(dict, 'a' + @as(u8, @intCast(round % 26))),
        }
        var input: std.ArrayListUnmanaged(u8) = .empty;
        defer input.deinit(gpa);
        const n_pieces = r.uintLessThan(usize, 12);
        for (0..n_pieces) |_| {
            switch (r.uintLessThan(u8, 3)) {
                0 => if (dlen != 0) {
                    const a = r.uintLessThan(usize, dlen);
                    const l = r.uintLessThan(usize, @min(dlen - a, 3000) + 1);
                    try input.appendSlice(gpa, dict[a..][0..l]);
                },
                1 => for (0..r.uintLessThan(usize, 200)) |_| try input.append(gpa, r.int(u8)),
                else => try input.appendNTimes(gpa, r.int(u8), r.uintLessThan(usize, 300)),
            }
        }
        var pd = try PreparedDictionary.init(gpa, dict);
        defer pd.deinit(gpa);
        const wbits: ?u5 = if (round % 5 == 0) 10 else null;
        inline for (.{ Effort.q0, .q1, .q4, .q6, .q9, .q11 }) |e| {
            const raw = try compressWith(gpa, input.items, .{ .effort = e, .dictionary = dict, .window_bits = wbits, .block_size = if (round % 7 == 0) 1000 else compressed_block_size });
            defer gpa.free(raw);
            const prep = try compressWith(gpa, input.items, .{ .effort = e, .prepared_dictionary = &pd, .window_bits = wbits, .block_size = if (round % 7 == 0) 1000 else compressed_block_size });
            defer gpa.free(prep);
            try testing.expectEqualSlices(u8, raw, prep);
            const back = try @import("decoder.zig").decompress(gpa, prep, .{ .dictionary = dict });
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, input.items, back);
        }
    }
}

test "the wide hasher where google uses H6/H68: q6/q9, a hint of 1 MiB, a window of 19..24" {
    try testing.expectEqual(Core.Kind.wide, Core.kindFor(.q6, 22, 1 << 20));
    try testing.expectEqual(Core.Kind.wide, Core.kindFor(.q9, 19, 5 << 20));
    try testing.expectEqual(Core.Kind.wide, Core.kindFor(.q9, 24, 1 << 20));
    try testing.expectEqual(Core.Kind.deep, Core.kindFor(.q6, 22, (1 << 20) - 1));
    try testing.expectEqual(Core.Kind.deep, Core.kindFor(.q9, 18, 5 << 20));
    try testing.expectEqual(Core.Kind.deep, Core.kindFor(.q9, 25, 5 << 20)); // (google: H65)
    try testing.expectEqual(Core.Kind.deep, Core.kindFor(.q11, 22, 5 << 20)); // (google: H10)
    try testing.expectEqual(Core.Kind.fast, Core.kindFor(.q4, 22, 5 << 20));
    try testing.expectEqual(Core.Kind.frag, Core.kindFor(.q1, 22, 5 << 20));
    // google's H6 hash: the low five bytes, from `kHashMul64 << 24`.
    var m = try WideMatcher.init(testing.allocator, 32, Effort.q6.wideSlotsLog());
    defer m.deinit(testing.allocator);
    m.setData("abcdeXabcdeY");
    try testing.expectEqual(m.hash(0), m.hash(6));
    m.setData("abcdeXabcdfY");
    try testing.expect(m.hash(0).bucket != m.hash(6).bucket or m.hash(0).tag != m.hash(6).tag);
    const v: u64 = std.mem.readInt(u64, "abcdeXab", .little);
    try testing.expectEqual(@as(usize, @intCast((v *% (@as(u64, 0x1FE35A7B_D3579BD3) << 24)) >> 49)), m.hash(0).bucket);
}
