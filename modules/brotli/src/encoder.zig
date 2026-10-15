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
//!   step. At `.default`/`.best` the last two distances are tried first (a
//!   copy at one of them needs no distance bits, from 3 bytes on).
//! - **`.fast` is its own algorithm** (`FastMatcher`, `buildCommandsFast`):
//!   4 slots of a 6-byte hash and the last distance, a lazy step only below
//!   32 bytes, sparse inserts inside long copies, growing steps through long
//!   literal runs. Sizes about google/brotli quality 4 (2026-10-14).
//! - **Distance short codes and implicit distances**: the encoder mirrors the
//!   decoder's ring of the last four distances (`DistRing`) and names a
//!   distance by its short code (0..15, no extra bits) when it can; a copy at
//!   the last distance whose lengths fit uses an implicit-distance command
//!   and no distance symbol at all.
//! - **Literal context modelling** (not at `.fast`): per-context histograms
//!   for the UTF8 and LSB6 modes, clustered greedily by estimated bits into
//!   at most 16 codes, the cheaper mode kept — and then checked on real bits
//!   against a single literal code, keeping the shorter block.
//! - **Distance contexts** (2026-10-15): the four distance contexts (copy
//!   length 2, 3, 4, 5+) share one to four codes, the cheapest partition.
//! - **`.max`** (2026-10-15): a shortest-path parse priced from the block's
//!   own statistics (`buildCommandsOptimal`) and static-dictionary words
//!   with their transforms (`DictSearch`); three parses, the shortest as
//!   written kept.
//!
//! ## What it deliberately does not do
//!
//! - No block splitting (`NBLTYPES` is always 1), no `NPOSTFIX`/`NDIRECT`
//!   tuning, no MSB6/SIGNED context modes (never the cheaper choice on the
//!   measured corpus), no OMIT_FIRST dictionary transforms, no dictionary
//!   words below `.max`.
//!
//! The result: `alice29.txt` 51 327 bytes at `.default` (reference q5: 52 809,
//! q9: 51 054, q11: 46 487), 50 536 at `.best`, 46 935 at `.max`; never worse
//! than store mode by more than the two-bit final-meta-block marker.
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
/// two only there (three at the others: two cost text 0.1 %).
const min_ring_match = 2;
/// Longest match searched for. Long runs (a file of zeros) are where a short
/// cap hurt most: 512 left `zeros` at 651 bytes, 65 535 at 26 (the reference's
/// q11: 14). Copy lengths themselves reach far higher (RFC 7932 copy code 23).
const max_match = 65535;

/// Errors that make the encoder give up on *compressing* a block. They never
/// escape `compress`: the block is stored verbatim instead.
const GiveUp = error{EncoderInvariant} || BrotliError;

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
/// was 5-10 % of `.max`).
fn distanceCode(d: u32, n: usize) ?struct { sym: u16, extra: u32, nbits: u5 } {
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
        for ([2]u16{ 4, 10 }, 0..) |first, which| {
            for (deltas, 0..) |delta, k| {
                if (@as(i64, self.last[which]) + delta == d) return first + @as(u16, @intCast(k));
            }
        }
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

    const idx = try gpa.alloc(u32, m);
    defer gpa.free(idx);
    {
        var k: usize = 0;
        for (counts, 0..) |c, s| {
            if (c != 0) {
                idx[k] = @intCast(s);
                k += 1;
            }
        }
    }
    // Ascending by count. max(count, floor) is monotone in count, so this one
    // order stays valid for every floor tried below.
    std.mem.sort(u32, idx, counts, struct {
        fn lt(cs: []const u32, a: u32, b: u32) bool {
            return cs[a] < cs[b];
        }
    }.lt);

    const cap = 2 * m; // m leaves + (m - 1) internal nodes
    const wt = try gpa.alloc(u64, cap);
    defer gpa.free(wt);
    const left = try gpa.alloc(u32, cap);
    defer gpa.free(left);
    const right = try gpa.alloc(u32, cap);
    defer gpa.free(right);
    const depth = try gpa.alloc(u8, cap);
    defer gpa.free(depth);

    var floor: u64 = 1;
    while (true) : (floor *= 2) {
        for (idx, 0..) |s, i| wt[i] = @max(counts[s], floor);

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
            for (idx, 0..) |s, j| lengths[s] = depth[j];
            return m;
        }
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
    var items: std.ArrayListUnmanaged(RleItem) = .empty;
    defer items.deinit(gpa);
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

    var cl_table = try huffman.buildComplex(gpa, &cl_lengths);
    defer cl_table.deinit(gpa);
    var cl_code = try codeFromTable(gpa, &cl_table, tables.code_length_codes);
    defer cl_code.deinit(gpa);

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
        if (cl_code.len[it.sym] == 0 and m != 1) return error.EncoderInvariant;
        try cl_code.emit(w, it.sym);
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
    _ = try assignLengths(gpa, counts, tables.max_code_length, lengths);
    try writeComplexCode(gpa, w, lengths);
    var table = try huffman.buildComplex(gpa, lengths);
    defer table.deinit(gpa);
    return codeFromTable(gpa, &table, alphabet_size);
}

// ---------------------------------------------------------------------------
// Match finding: bucketed hash over 4-byte hashes, one lazy step.
//
// Each hash bucket keeps the last `depth` positions inserted under it, in a
// ring of `depth` slots. Until 2026-10-14 this was a hash chain (`head` per
// hash, `prev` per position), walking up to `depth` links: every link is a
// load whose address is the previous load's value, so the walk was a chain of
// dependent cache accesses — half of `find`'s cycles waited on `prev[c]` and
// on the candidate byte that depends on it (perf, `.default` on text). A
// bucket names all its candidates at once, so their loads overlap.

const Match = struct { len: u32, dist: u32, gain: f32 };

/// Distances an explicit distance code reaches (NPOSTFIX = NDIRECT = 0):
/// the last code's offset plus its 24 extra bits.
const max_code_distance = (1 << 26) - 4;
/// A position no copy can come from (`shift` marks dropped ones with it):
/// never below the position searched.
const dropped_pos = std.math.maxInt(u32);

/// A raw prefix dictionary (RFC 9841 §3.2) sits at `data[0..len]`, the
/// output after it. A copy from the dictionary is named by the decoder's
/// distance `len + out_max - c` (`out_max` = how far back the output
/// reaches), and may run on past the dictionary's end only while the output
/// after it in `data` is what the decoder continues with — its first byte,
/// before anything was dropped and while all of the output is in reach.
const Prefix = struct {
    len: usize = 0,
    /// Output bytes dropped from `data` (`StreamWriter`'s history slid).
    dropped: usize = 0,

    /// How far back the output reaches from `p`: the window, or what was
    /// produced so far.
    fn outMax(x: Prefix, p: usize, max_dist: usize) usize {
        return @min(max_dist, p - x.len + x.dropped);
    }

    /// The decoder's distance to `c` from `p` (`c < len`), and the longest
    /// copy from there; null beyond what a distance code can name.
    inline fn reach(x: Prefix, p: usize, c: usize, out_max: usize, max_len: usize) ?struct { d: usize, cap: usize } {
        const d = x.len + out_max - c;
        if (d > max_code_distance) return null;
        const joined = x.dropped == 0 and out_max == p - x.len;
        return .{ .d = d, .cap = if (joined) max_len else @min(max_len, x.len - c) };
    }

    /// Positions in the dictionary stay; output ones move down by `by`, or
    /// become `dropped_pos` when they fall off.
    fn shiftPos(x: Prefix, s: u32, by: u32) u32 {
        if (s < x.len or s == dropped_pos) return s;
        return if (s - x.len < by) dropped_pos else s - by;
    }
};

/// log2 of a match finder's buckets for an input of `size` bytes: 2^8 at
/// least, one per byte up to 2^`max` — compressing a few hundred bytes must
/// not cost a fixed table.
fn bucketLog(size: usize, max: u6) u6 {
    var b: u6 = 8;
    while (b < max and (@as(usize, 1) << b) < size) b += 1;
    return b;
}

const Matcher = struct {
    /// Slots per bucket = candidates walked per lookup (`Effort.depth`), a
    /// power of two.
    depth: u32,
    /// Estimated bits a literal costs in the current block (its order-0
    /// entropy): what a match saves per byte it covers. Set per block.
    lit_cost: f32 = 8,
    /// `depth` slots per bucket, positions. A slot is read only when the
    /// bucket's count says it was written.
    slots: []u32,
    /// Positions ever inserted per bucket (the next slot is `count % depth`).
    count: []u32,
    depth_log: u5,
    hash_shift: u5,
    data: []const u8,
    /// The decoder's last four distances as the commands so far leave them
    /// (`buildCommands` keeps it): a copy at one of them is named by a short
    /// code with no extra bits, so it is tried first and priced lower.
    ring: DistRing = .{},
    prefix: Prefix = .{},

    /// Tables for an input of about `size` bytes; `data` is set by the
    /// caller.
    fn init(gpa: std.mem.Allocator, size: usize, depth: u32, slots_log_max: u5) std.mem.Allocator.Error!Matcher {
        std.debug.assert(std.math.isPowerOfTwo(depth));
        const depth_log: u5 = @intCast(std.math.log2_int(u32, depth));
        // Buckets sized to the input — compressing a few hundred bytes must
        // not cost a fixed table — and capped so all slots together stay at
        // `slots_log_max` (a deeper bucket means fewer of them).
        const bucket_log: u5 = @intCast(bucketLog(size, slots_log_max - depth_log));

        const count = try gpa.alloc(u32, @as(usize, 1) << bucket_log);
        errdefer gpa.free(count);
        // `slots` is left as allocated: only the slots a bucket's count
        // covers are read, and each was written first.
        const slots = try gpa.alloc(u32, @as(usize, 1) << (bucket_log + depth_log));
        fillZero(count);
        return .{
            .depth = depth,
            .slots = slots,
            .count = count,
            .depth_log = depth_log,
            .hash_shift = @intCast(32 - @as(u6, bucket_log)),
            .data = &.{},
        };
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

    fn deinit(self: *Matcher, gpa: std.mem.Allocator) void {
        gpa.free(self.slots);
        gpa.free(self.count);
        self.* = undefined;
    }

    /// Empty, as `init` leaves it.
    fn reset(self: *Matcher) void {
        fillZero(self.count);
        self.ring = .{};
    }

    /// `by` output bytes left `data` (`Prefix.shiftPos`). Only the slots a
    /// count covers hold positions; the rest are shifted as garbage.
    fn shift(self: *Matcher, by: u32) void {
        for (self.slots) |*s| s.* = self.prefix.shiftPos(s.*, by);
        self.prefix.dropped += by;
    }

    fn hash(self: *const Matcher, p: usize) usize {
        const v = std.mem.readInt(u32, self.data[p..][0..4], .little);
        return (v *% 0x1e35a7bd) >> self.hash_shift;
    }

    /// Start loading the bucket `p` hashes to: positions are visited in
    /// order, so the next lookup's bucket can be on its way while this one
    /// is compared.
    fn prefetch(self: *const Matcher, p: usize) void {
        if (p + min_match > self.data.len) return;
        const h = self.hash(p);
        @prefetch(&self.count[h], .{});
        @prefetch(&self.slots[h << self.depth_log], .{});
    }

    fn insert(self: *Matcher, p: usize) void {
        if (p + min_match > self.data.len) return;
        const h = self.hash(p);
        const n = self.count[h];
        self.slots[(h << self.depth_log) | (n & (self.depth - 1))] = @intCast(p);
        self.count[h] = n +% 1;
    }

    /// The match's estimated saving in bits: the literals it replaces minus
    /// what naming it costs — the distance's extra bits (about log2 of it)
    /// and a few bits of command and distance symbol. On text a literal costs
    /// 4-5 bits and nearly every match pays; on random bytes over a small
    /// alphabet a literal costs 2-3 and a far, short match loses (measured:
    /// `alpha5_flat` 10 417 bytes with the longest match taken, worse the
    /// deeper the search looked, against ~9 000 for no matches at all).
    fn gain(self: *const Matcher, len: usize, dist: usize) f32 {
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
    /// `px`: a prefix dictionary may be in `data` — comptime, so a search
    /// without one compiles to the loop it was before dictionaries (the
    /// per-candidate test cost `.best` 20 %, measured 2026-10-15).
    fn find(self: *const Matcher, comptime ring_n: u3, comptime px: bool, p: usize, max_dist: usize, limit: usize) ?Match {
        if (p + min_match > limit) return null;
        const max_len = @min(limit - p, max_match);
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
                if (l < @as(usize, if (i == 0) min_ring_match else 3)) continue;
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
        const h = self.hash(p);
        const n = self.count[h];
        // Newest first; a wrapped count still means a full bucket.
        const valid = if (n < self.depth) n else self.depth;
        const bucket = self.slots[h << self.depth_log ..][0..self.depth];
        var k: u32 = 0;
        while (k < valid) : (k += 1) {
            const c: usize = bucket[(n -% 1 -% k) & (self.depth - 1)];
            if (c >= p) continue;
            var d = p - c;
            var cap: usize = max_len;
            if (px and c < self.prefix.len) {
                const r = self.prefix.reach(p, c, max_dist, max_len) orelse continue;
                d = r.d;
                cap = r.cap;
            } else if (d > max_dist) {
                // Older slots are further back still — but for the
                // dictionary's, which are oldest of all.
                if (px) continue;
                break;
            }
            // Cheap reject: a candidate that cannot beat `best_len` is skipped
            // before the byte-by-byte compare.
            if (best_len == 0 or self.data[c + best_len] == self.data[p + best_len]) {
                const l = matchLen(self.data, c, p, cap);
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

    /// Every copy for `p` that is longer than any nearer one (so the
    /// candidates' lengths rise and their distances too), as `find` walks the
    /// bucket: what a shortest-path parse chooses from (`.max`). Returns how
    /// many of `out` are set.
    fn collect(self: *const Matcher, comptime px: bool, p: usize, max_dist: usize, limit: usize, out: *[max_cands]Cand) usize {
        if (p + min_match > limit) return 0;
        const max_len = @min(limit - p, max_match);
        const h = self.hash(p);
        const n = self.count[h];
        const valid = if (n < self.depth) n else self.depth;
        const bucket = self.slots[h << self.depth_log ..][0..self.depth];
        var found: usize = 0;
        var best_len: usize = 0;
        var k: u32 = 0;
        while (k < valid) : (k += 1) {
            const c: usize = bucket[(n -% 1 -% k) & (self.depth - 1)];
            if (c >= p) continue;
            var d = p - c;
            var cap: usize = max_len;
            if (px and c < self.prefix.len) {
                const r = self.prefix.reach(p, c, max_dist, max_len) orelse continue;
                d = r.d;
                cap = r.cap;
            } else if (d > max_dist) {
                if (px) continue;
                break;
            }
            if (best_len == 0 or self.data[c + best_len] == self.data[p + best_len]) {
                const l = matchLen(self.data, c, p, cap);
                if (l >= min_match and l > best_len) {
                    out[found] = .{ .len = @intCast(l), .dist = @intCast(d) };
                    found += 1;
                    best_len = l;
                    if (l == max_len or found == max_cands) break;
                }
            }
        }
        return found;
    }
};

/// A copy `Matcher.collect` found: length and the decoder's distance.
const Cand = struct { len: u32, dist: u32 };
/// Most candidates kept for a position — the parse's memory: 8 bytes each
/// per position of the block. 16, 32 and 48 gave the same sizes on the bench
/// payloads (2026-10-15).
const max_cands = 16;

// `.fast` has a match finder of its own (2026-10-14). `Matcher` keeps a count
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
/// `literalCost` sampling at `.fast`.
const fast_cost_stride = 4;

const FastMatcher = struct {
    lit_cost: f32 = 8,
    prefix: Prefix = .{},
    /// `fast_sweep` slots per bucket.
    table: []u32,
    hash_shift: u6,
    data: []const u8,

    /// Tables for an input of about `size` bytes; `data` is set by the
    /// caller.
    fn init(gpa: std.mem.Allocator, size: usize, bucket_log_max: u6) std.mem.Allocator.Error!FastMatcher {
        const bucket_log = bucketLog(size, bucket_log_max);
        const table = try gpa.alloc(u32, @as(usize, 1) << bucket_log << std.math.log2_int(u32, fast_sweep));
        Matcher.fillZero(table);
        return .{ .table = table, .hash_shift = @intCast(64 - @as(u7, bucket_log)), .data = &.{} };
    }

    fn deinit(self: *FastMatcher, gpa: std.mem.Allocator) void {
        gpa.free(self.table);
        self.* = undefined;
    }

    /// Empty, as `init` leaves it.
    fn reset(self: *FastMatcher) void {
        Matcher.fillZero(self.table);
    }

    /// As `Matcher.shift`.
    fn shift(self: *FastMatcher, by: u32) void {
        for (self.table) |*s| s.* = self.prefix.shiftPos(s.*, by);
        self.prefix.dropped += by;
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
            var d = p - c;
            var cap: usize = max_len;
            if (px and c < self.prefix.len) {
                const r = self.prefix.reach(p, c, max_dist, max_len) orelse continue;
                d = r.d;
                cap = r.cap;
            } else if (d > max_dist) continue;
            if (d == best_dist) continue;
            if (self.data[c + best_len] != self.data[p + best_len]) continue;
            const l = Matcher.matchLen(self.data, c, p, cap);
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
        if (best_len == 0) return null;
        return .{ .len = @intCast(best_len), .dist = @intCast(best_dist), .gain = best_gain };
    }
};

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
    /// Zero for a copy. For a static-dictionary word (RFC 7932 §8, `.max`):
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
    comptime px: bool,
    gpa: std.mem.Allocator,
    matcher: *Matcher,
    start: usize,
    end: usize,
    max_dist: usize,
    out: *std.ArrayListUnmanaged(Cmd),
) std.mem.Allocator.Error!void {
    var p = start;
    var lit_start = start;
    var pending: ?Match = null;
    // A local copy: read through `matcher` it would be loaded again at
    // every position.
    const x = matcher.prefix;
    matcher.lit_cost = literalCost(matcher.data[start..end], 1);

    while (p < end) {
        matcher.prefetch(p + 1);
        const m = pending orelse matcher.find(ring_n, px, p, x.outMax(p, max_dist), end);
        pending = null;
        if (m == null) {
            matcher.insert(p);
            p += 1;
            continue;
        }
        matcher.insert(p);
        if (p + 1 < end) {
            if (matcher.find(ring_n, px, p + 1, x.outMax(p + 1, max_dist), end)) |b| {
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
        try out.append(gpa, .{
            .insert_len = @intCast(p - lit_start),
            .copy_len = len,
            .dist = m.?.dist,
        });
        // `DistRing.update` pushes every distance but the last one (code 0).
        if (ring_n != 0 and m.?.dist != matcher.ring.last[0]) matcher.ring.update(m.?.dist, null);
        matcher.prefetch(p + len);
        var q = p + 1;
        while (q < p + len) : (q += 1) matcher.insert(q);
        p += len;
        lit_start = p;
    }

    if (lit_start < end) {
        try out.append(gpa, .{ .insert_len = @intCast(end - lit_start), .copy_len = 0, .dist = 0 });
    }
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

/// `.fast`'s parse of `input[start..end)`, same contract as `buildCommands`:
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
    const x = matcher.prefix; // as in `buildCommands`
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
// `.max`: a shortest-path parse. Every position keeps the cheapest way to have
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

const OptNode = struct {
    cost: f32,
    /// Where the path came from: the start of the copy, or the position
    /// before a literal.
    from: u32,
    /// Copy length; 0 for a literal.
    len: u32,
    dist: u32,
    /// Literals since the last copy on this path.
    ins: u32,
    ring: [4]u32,
    /// A dictionary word's length (`len` is what its transform produces);
    /// 0 for a copy or a literal.
    word: u8 = 0,
};

const OptCosts = struct {
    cmd: [tables.num_command_symbols]f32,
    dist: [dist_contexts][dist_alphabet_large]f32,
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
fn fitCosts(gpa: std.mem.Allocator, costs: *OptCosts, cmds: []const Cmd, ring0: DistRing, n_dist: usize, model: *const LiteralModel) std.mem.Allocator.Error!void {
    const cmd_h = try gpa.alloc(u32, tables.num_command_symbols);
    defer gpa.free(cmd_h);
    @memset(cmd_h, 0);
    var dist_h: [dist_contexts][dist_alphabet_large]u32 = @splat(@splat(0));
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
                const s = short orelse (distanceCode(c.dist, n_dist) orelse continue).sym;
                dist_h[distContext(c.copy_len)][s] += 1;
            }
            if (c.out_len == 0) ring.update(c.dist, short);
        }
    }
    bitsOf(cmd_h, &costs.cmd, 8);
    for (&dist_h, &costs.dist) |*h, *o| bitsOf(h[0..n_dist], o[0..n_dist], 6);
    for (model.counts[0..model.ntrees], 0..) |*h, t| bitsOf(h, &costs.lit[t], 8);
}

/// Relax the copies of lengths `lo..hi` (inclusive) at distance `d` from
/// node `i`: one command each, priced with the node's insert length `ic` and
/// ring.
fn relaxCopies(
    nodes: []OptNode,
    costs: *const OptCosts,
    nd: OptNode,
    ic: LenCode,
    i: usize,
    lo: u32,
    hi: u32,
    d: u32,
    n_dist: usize,
) void {
    const ring: DistRing = .{ .last = nd.ring };
    const short = ring.shortCode(d);
    var dist_bits: [dist_contexts]f32 = undefined;
    if (short) |s| {
        for (&dist_bits, costs.dist) |*b, row| b.* = row[s];
    } else {
        const dc = distanceCode(d, n_dist) orelse return;
        for (&dist_bits, costs.dist) |*b, row| b.* = row[dc.sym] + @as(f32, @floatFromInt(dc.nbits));
    }
    const new_ring: [4]u32 = if (d == nd.ring[0]) nd.ring else .{ d, nd.ring[0], nd.ring[1], nd.ring[2] };
    var l = lo;
    while (l <= hi) : (l += 1) {
        const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, l) orelse continue;
        const implicit = cmd_tables.implicit[ic.code][cc.code];
        var bits: f32 = @floatFromInt(@as(u32, ic.nbits) + cc.nbits);
        if (implicit != 0xffff and short == 0) {
            bits += costs.cmd[implicit];
        } else {
            bits += costs.cmd[cmd_tables.sym[ic.code][cc.code]] + dist_bits[distContext(l)];
        }
        const c = nd.cost + bits;
        const t = &nodes[i + l];
        if (c < t.cost) t.* = .{ .cost = c, .from = @intCast(i), .len = l, .dist = d, .ins = 0, .ring = new_ring };
    }
}

/// Relax the dictionary word `dc` at node `i`, named by the distance `d`.
fn relaxWord(nodes: []OptNode, costs: *const OptCosts, nd: OptNode, ic: LenCode, i: usize, dc: DictCand, d: u32, n_dist: usize) void {
    const cc = lengthCode(&cmd_tables.copy_off, &cmd_tables.copy_nbits, dc.n) orelse return;
    const dcode = distanceCode(d, n_dist) orelse return;
    const bits = @as(f32, @floatFromInt(@as(u32, ic.nbits) + cc.nbits + dcode.nbits)) +
        costs.cmd[cmd_tables.sym[ic.code][cc.code]] + costs.dist[distContext(dc.n)][dcode.sym];
    const c = nd.cost + bits;
    const t = &nodes[i + dc.wl];
    if (c < t.cost) t.* = .{ .cost = c, .from = @intCast(i), .len = dc.wl, .dist = d, .ins = 0, .ring = nd.ring, .word = dc.n };
}

/// A copy `greedyParse` chose and its estimated saving in bits.
const Pick = struct { len: u32, dist: u32, gain: f32 };

/// A greedy, one-step-lazy parse over the candidates `collect` found: what
/// `buildCommands` makes, without a match finder of its own. The first
/// contender of `.max` (a small block is often best served by it) and the
/// prices of the next.
fn greedyParse(
    gpa: std.mem.Allocator,
    data: []const u8,
    start: usize,
    end: usize,
    x: Prefix,
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
    x: Prefix,
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

/// The shortest-path parse of `data[start..end)` for `.max`: `max_parses`
/// passes, each priced from the commands of the one before. Matches may reach
/// back before `start` but never past `end`.
fn buildCommandsOptimal(
    comptime px: bool,
    gpa: std.mem.Allocator,
    matcher: *Matcher,
    start: usize,
    end: usize,
    max_dist: usize,
    ring0: DistRing,
    n_dist: usize,
    /// Null with a prefix dictionary: distances there count from its end.
    dsearch: ?*const DictSearch,
    parses: *[max_parses]std.ArrayListUnmanaged(Cmd),
) std.mem.Allocator.Error!void {
    const n = end - start;
    const x = matcher.prefix;
    const data = matcher.data;

    // Every position's candidates, found once. A copy of `max_take_len` is
    // taken whole, so the positions inside it get none.
    const offs = try gpa.alloc(u32, n + 1);
    defer gpa.free(offs);
    var cands: std.ArrayListUnmanaged(Cand) = .empty;
    defer cands.deinit(gpa);
    var buf: [max_cands]Cand = undefined;
    const doffs = try gpa.alloc(u32, n + 1);
    defer gpa.free(doffs);
    var dcands: std.ArrayListUnmanaged(DictCand) = .empty;
    defer dcands.deinit(gpa);
    var dbuf: [max_dict_cands]DictCand = undefined;
    var p = start;
    while (p < end) {
        offs[p - start] = @intCast(cands.items.len);
        doffs[p - start] = @intCast(dcands.items.len);
        const found = matcher.collect(px, p, x.outMax(p, max_dist), end, &buf);
        try cands.appendSlice(gpa, buf[0..found]);
        var step: usize = 1;
        if (found > 0 and buf[found - 1].len >= max_take_len) {
            step = buf[found - 1].len;
        } else if (dsearch) |d| {
            const nd = d.find(data, p, end, &dbuf);
            try dcands.appendSlice(gpa, dbuf[0..nd]);
        }
        matcher.insert(p);
        var q = p + 1;
        while (q < p + step) : (q += 1) {
            offs[q - start] = @intCast(cands.items.len);
            doffs[q - start] = @intCast(dcands.items.len);
            matcher.insert(q);
        }
        p += step;
    }
    offs[n] = @intCast(cands.items.len);
    doffs[n] = @intCast(dcands.items.len);

    const nodes = try gpa.alloc(OptNode, n + 1);
    defer gpa.free(nodes);
    const lit_cost = try gpa.alloc(f32, n);
    defer gpa.free(lit_cost);
    const model = try gpa.create(LiteralModel);
    defer gpa.destroy(model);
    const costs = try gpa.create(OptCosts);
    defer gpa.destroy(costs);

    // The first parse: greedy, by the saving per candidate.
    parses[0].clearRetainingCapacity();
    try greedyParse(gpa, data, start, end, x, max_dist, offs, cands.items, ring0, &parses[0]);

    const inf = std.math.inf(f32);
    var pass: usize = 1;
    while (pass < max_parses) : (pass += 1) {
        const out = &parses[pass];
        out.clearRetainingCapacity();
        const prev = parses[pass - 1].items;
        try chooseLiteralModel(gpa, data[x.len..], start - x.len, prev, .max, model);
        try fitCosts(gpa, costs, prev, ring0, n_dist, model);
        for (model.counts[0..model.ntrees], 0..) |*h, t| bitsOf(h, &costs.lit[t], 8);
        for (lit_cost, 0..) |*lc, i| {
            const q = start + i;
            const o = q - x.len;
            const p1: u8 = if (o >= 1) data[q - 1] else 0;
            const p2: u8 = if (o >= 2) data[q - 2] else 0;
            lc.* = costs.lit[model.map[contextId(model.mode, p1, p2)]][data[q]];
        }

        for (nodes) |*nd| nd.cost = inf;
        nodes[0] = .{ .cost = 0, .from = 0, .len = 0, .dist = 0, .ins = 0, .ring = ring0.last };
        var i: usize = 0;
        while (i < n) {
            const nd = nodes[i];
            if (nd.cost == inf) {
                i += 1;
                continue;
            }
            const pos = start + i;
            const lc = nd.cost + lit_cost[i];
            if (lc < nodes[i + 1].cost) nodes[i + 1] = .{ .cost = lc, .from = @intCast(i), .len = 0, .dist = 0, .ins = nd.ins + 1, .ring = nd.ring };
            const ic = lengthCode(&cmd_tables.insert_off, &cmd_tables.insert_nbits, nd.ins) orelse {
                i += 1;
                continue;
            };
            var take: u32 = 0;
            var prev_len: u32 = min_match - 1;
            for (cands.items[offs[i]..offs[i + 1]]) |cd| {
                if (cd.len <= prev_len) continue;
                const whole = cd.len >= max_take_len;
                relaxCopies(nodes, costs, nd, ic, i, if (whole) cd.len else prev_len + 1, cd.len, cd.dist, n_dist);
                prev_len = cd.len;
                if (whole) take = cd.len;
            }
            // The ring's distances, not only those a bucket named.
            const reach = x.outMax(pos, max_dist);
            const max_len = @min(end - pos, max_match);
            for (nd.ring, 0..) |d, r| {
                if (pos + 4 > end) break;
                if (d == 0 or d > reach) continue;
                if (std.mem.indexOfScalar(u32, nd.ring[0..r], d) != null) continue;
                const c = pos - d;
                const head: u32 = std.mem.readInt(u32, data[pos..][0..4], .little) & 0xffff;
                if (std.mem.readInt(u32, data[c..][0..4], .little) & 0xffff != head) continue;
                const l: u32 = @intCast(Matcher.matchLen(data, c, pos, max_len));
                if (l < min_ring_match) continue;
                const whole = l >= max_take_len;
                relaxCopies(nodes, costs, nd, ic, i, if (whole) l else min_ring_match, l, d, n_dist);
                if (whole) take = @max(take, l);
            }
            for (dcands.items[doffs[i]..doffs[i + 1]]) |dc| {
                if (i + dc.wl > n) continue;
                const word_id: u32 = dc.idx + (@as(u32, dc.t) << @intCast(dictionary.size_bits_by_length[dc.n]));
                relaxWord(nodes, costs, nd, ic, i, dc, @intCast(reach + 1 + word_id), n_dist);
            }
            // Past the inside of a copy taken whole — unless it could not be
            // named, and the node after it was not reached.
            i += if (take != 0 and nodes[i + take].cost != inf) take else 1;
        }

        // The path from the end back, copies last-to-first, then reversed.
        var at: usize = n;
        while (at > 0) {
            const nd = nodes[at];
            if (nd.len == 0) {
                at -= 1;
                continue;
            }
            try out.append(gpa, if (nd.word != 0)
                .{ .insert_len = nd.from, .copy_len = nd.word, .dist = nd.dist, .out_len = nd.len }
            else
                .{ .insert_len = nd.from, .copy_len = nd.len, .dist = nd.dist });
            at = nd.from;
        }
        // `insert_len` holds the copy's start for now.
        std.mem.reverse(Cmd, out.items);
        var cur: u32 = 0;
        for (out.items) |*c| {
            const s = c.insert_len;
            c.insert_len = s - cur;
            cur = s + c.produced();
        }
        if (cur < n) try out.append(gpa, .{ .insert_len = @intCast(n - cur), .copy_len = 0, .dist = 0 });
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

/// Cluster the per-context histograms of `mode` for `input[start..end)`'s
/// literals (`lits` marks literal positions) and return the model with its
/// estimated cost.
fn clusterLiterals(input: []const u8, start: usize, cmds: []const Cmd, mode: u2, scratch: *ClusterScratch, out: *LiteralModel) f64 {
    const hist = &scratch.hist;
    hist.* = @splat(@splat(0));
    var pos = start;
    for (cmds) |c| {
        for (0..c.insert_len) |k| {
            const q = pos + k;
            const p1: u8 = if (q >= 1) input[q - 1] else 0;
            const p2: u8 = if (q >= 2) input[q - 2] else 0;
            hist[contextId(mode, p1, p2)][input[q]] += 1;
        }
        pos += c.insert_len + c.produced();
    }

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

/// The literal model for a block: context-free (one code) at `.fast`, or
/// when the literals are too few or too random for contexts to pay; else the
/// cheapest clustering over the UTF8, LSB6 and SIGNED context modes. SIGNED
/// wins on fonts (TTF: 1.2–2.2 % smaller than UTF8, 2026-10-15; google picks
/// it there too); MSB6 never won on anything measured, so it is not tried.
fn chooseLiteralModel(gpa: std.mem.Allocator, input: []const u8, start: usize, cmds: []const Cmd, effort: Effort, out: *LiteralModel) std.mem.Allocator.Error!void {
    out.* = .{};

    var n_lits: u64 = 0;
    var pos = start;
    for (cmds) |c| {
        for (input[pos..][0..c.insert_len]) |b| out.counts[0][b] += 1;
        n_lits += c.insert_len;
        pos += c.insert_len + c.produced();
    }
    out.single = out.counts[0];
    if (effort == .fast or n_lits < 256) return;
    // Near 8 bits a literal: no context will find structure a single code
    // misses (random or already-compressed bytes).
    if (histogramCost(&out.counts[0]) > 7.9 * @as(f64, @floatFromInt(n_lits))) return;

    const scratch = try gpa.create(ClusterScratch);
    defer gpa.destroy(scratch);
    const single = histogramCost(&out.counts[0]);
    var best_cost = single;
    var trial: LiteralModel = undefined;
    // Literals that are nearly all ASCII: UTF8 alone (it won on every such
    // block measured — text, HTML, JSON — and clustering is a tenth of
    // `.default`'s time per mode).
    var ascii: u64 = 0;
    for (out.single[0..0x80]) |c| ascii += c;
    const modes: []const u2 = if (ascii * 100 >= n_lits * ascii_pct) &.{2} else &.{ 2, 0, 3 };
    for (modes) |mode| {
        const c = clusterLiterals(input, start, cmds, mode, scratch, &trial);
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

/// NTREES and, above one tree, the map: no run-length codes (RLEMAX = 0), a
/// prefix code over the tree ids, no inverse move-to-front.
fn writeContextMap(gpa: std.mem.Allocator, w: *BitWriter, map: []const u8, ntrees: u8) GiveUp!void {
    try writeVarLenUint8(w, ntrees - 1);
    if (ntrees == 1) return;
    try w.writeBits(0, 1); // RLEMAX = 0
    var counts = [_]u32{0} ** 256;
    for (map) |v| counts[v] += 1;
    var code = try buildAndWriteCode(gpa, w, counts[0..ntrees], ntrees);
    defer code.deinit(gpa);
    for (map) |v| try code.emit(w, v);
    try w.writeBits(0, 1); // IMTF = 0
}

// ---------------------------------------------------------------------------
// Meta-block writers.

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
    const res = try gpa.alloc(Resolved, cmds.len);
    defer gpa.free(res);

    const cmd_counts = try gpa.alloc(u32, tables.num_command_symbols);
    defer gpa.free(cmd_counts);
    @memset(cmd_counts, 0);
    var dist_counts: [dist_contexts][dist_alphabet_large]u32 = @splat(@splat(0));
    const n_dist: u32 = if (env.large_window) dist_alphabet_large else dist_alphabet_size;

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
                const dc = distanceCode(c.dist, n_dist) orelse return error.EncoderInvariant;
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

    const model = try gpa.create(LiteralModel);
    defer gpa.destroy(model);
    try chooseLiteralModel(gpa, input, start, cmds, if (single_literal_code) .fast else effort, model);
    // Every code needs at least one symbol even when unused.
    var padded: [max_literal_trees]bool = @splat(false);
    for (model.counts[0..model.ntrees], 0..) |*h, t| {
        var any = false;
        for (h) |c| {
            if (c != 0) any = true;
        }
        if (!any) {
            h[0] = 1;
            padded[t] = true;
        }
    }

    // The distance contexts that share a code, by estimated bits.
    var dist_map: [dist_contexts]u8 = undefined;
    const dist_trees = clusterDistances(&dist_counts, n_dist, &dist_map);
    var dist_tree_counts: [dist_contexts][dist_alphabet_large]u32 = @splat(@splat(0));
    for (0..dist_contexts) |ctx| {
        for (dist_counts[ctx][0..n_dist], dist_tree_counts[dist_map[ctx]][0..n_dist]) |c, *t| t.* += c;
    }
    // Every code needs at least one symbol even when unused.
    for (dist_tree_counts[0..dist_trees]) |*h| {
        var any = false;
        for (h[0..n_dist]) |c| {
            if (c != 0) any = true;
        }
        if (!any) h[0] = 1;
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

    // NBLTYPES = 1 for literals, commands and distances (varlen uint8 zero).
    try w.writeBits(0, 1);
    try w.writeBits(0, 1);
    try w.writeBits(0, 1);
    // NPOSTFIX = 0, NDIRECT = 0.
    try w.writeBits(0, 6);
    // One literal block type => one context mode.
    try w.writeBits(model.mode, 2);
    // The literal context map; the distance map is a single tree (one zero
    // bit, the map implicitly all zeros).
    const map_from = w.bitPos();
    try writeContextMap(gpa, w, &model.map, model.ntrees);
    var lit_part = w.bitPos() - map_from;
    if (dist_trees == 1) {
        try w.writeBits(0, 1);
    } else {
        try writeContextMap(gpa, w, &dist_map, @intCast(dist_trees));
    }

    var lit_codes: [max_literal_trees]Code = undefined;
    var built: usize = 0;
    defer for (lit_codes[0..built]) |*c| c.deinit(gpa);
    const codes_from = w.bitPos();
    while (built < model.ntrees) : (built += 1) {
        lit_codes[built] = try buildAndWriteCode(gpa, w, &model.counts[built], tables.num_literal_symbols);
    }
    lit_part += w.bitPos() - codes_from;

    // With more than one literal code, price the one-code alternative on
    // exact bits: it differs from this block only in the context map, the
    // literal code headers and the literal symbols, all known before a
    // literal is written. `compressWith` writes it only when it is no
    // longer — rather than writing every such block twice.
    var single_no_worse = false;
    if (model.ntrees > 1) {
        for (model.counts[0..model.ntrees], lit_codes[0..model.ntrees], padded[0..model.ntrees]) |*h, *code, pad| {
            if (pad) continue;
            for (h, code.len) |c, l| lit_part += @as(usize, c) * l;
        }
        var scratch = BitWriter{ .gpa = gpa };
        defer scratch.buf.deinit(gpa);
        try writeContextMap(gpa, &scratch, &.{}, 1);
        var single_code = try buildAndWriteCode(gpa, &scratch, &model.single, tables.num_literal_symbols);
        defer single_code.deinit(gpa);
        var single_part = scratch.bitPos();
        for (model.single, single_code.len) |c, l| single_part += @as(usize, c) * l;
        single_no_worse = single_part <= lit_part;
    }
    var cmd_code = try buildAndWriteCode(gpa, w, cmd_counts, tables.num_command_symbols);
    defer cmd_code.deinit(gpa);
    var dist_codes: [dist_contexts]Code = undefined;
    var dist_built: usize = 0;
    defer for (dist_codes[0..dist_built]) |*c| c.deinit(gpa);
    while (dist_built < dist_trees) : (dist_built += 1) {
        dist_codes[dist_built] = try buildAndWriteCodeWide(gpa, w, dist_tree_counts[dist_built][0..n_dist], n_dist, if (env.large_window) dist_alphabet_large_max else dist_alphabet_size);
    }

    // --- commands -----------------------------------------------------------
    lit_pos = start;
    for (cmds, res) |c, r| {
        try cmd_code.emit(w, r.sym);
        if (r.insert_nbits != 0) try w.writeBits(r.insert_extra, r.insert_nbits);
        if (r.copy_nbits != 0) try w.writeBits(r.copy_extra, r.copy_nbits);
        const lits = input[lit_pos..][0..c.insert_len];
        if (model.ntrees == 1) {
            // No context to look up; two codes of at most 15 bits fit one
            // `writeBits`.
            const code = &lit_codes[0];
            var k: usize = 0;
            while (k + 2 <= lits.len) : (k += 2) {
                const l0: u5 = @intCast(code.len[lits[k]]);
                const l1: u5 = @intCast(code.len[lits[k + 1]]);
                try w.writeBits(@as(u32, code.bits[lits[k]]) | @as(u32, code.bits[lits[k + 1]]) << l0, @as(u6, l0) + l1);
            }
            if (k < lits.len) try code.emit(w, lits[k]);
        } else {
            for (lit_pos..lit_pos + c.insert_len) |q| {
                const p1: u8 = if (q >= 1) input[q - 1] else 0;
                const p2: u8 = if (q >= 2) input[q - 2] else 0;
                try lit_codes[model.map[contextId(model.mode, p1, p2)]].emit(w, input[q]);
            }
        }
        lit_pos += c.insert_len;
        if (r.has_dist) {
            try dist_codes[dist_map[r.dist_ctx]].emit(w, r.dist_sym);
            if (r.dist_nbits != 0) try w.writeBits(r.dist_extra, r.dist_nbits);
        }
        lit_pos += c.produced();
    }
    return .{ .ntrees = model.ntrees, .single_no_worse = single_no_worse };
}

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
fn clusterDistances(counts: *const [dist_contexts][dist_alphabet_large]u32, n_dist: usize, map: *[dist_contexts]u8) usize {
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
        var merged: [dist_alphabet_large]u32 = undefined;
        for (0..groups) |g| {
            @memset(merged[0..n_dist], 0);
            for (0..dist_contexts) |ctx| {
                if (cand[ctx] != g) continue;
                for (merged[0..n_dist], counts[ctx][0..n_dist]) |*m, c| m.* += c;
            }
            cost += sliceCost(merged[0..n_dist]);
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
};

/// The bytes the dictionary word of command `c` stands for, made as the
/// decoder makes them, are `expect` (RFC 7932 §8); `pos` is the decoder's
/// output position before it. A word that would decode to anything else is
/// an encoder bug: the block is stored instead of carrying it.
fn checkWord(c: Cmd, pos: usize, env: BlockEnv, expect: []const u8) GiveUp!void {
    const n = c.copy_len;
    if (n < dictionary.min_word_length or n > dictionary.max_word_length) return error.EncoderInvariant;
    if (env.reach != env.dropped) return error.EncoderInvariant; // never with a prefix dictionary
    const max_distance = @min(pos, env.max_backward);
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
    /// Literal codes the block used.
    ntrees: u8,
    /// With `ntrees > 1`: the same block with one literal code would be no
    /// longer (exact bits).
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

/// How hard the encoder looks. Every level emits a valid stream and falls
/// back to storing a block that will not shrink; they differ in time spent.
pub const Effort = enum {
    /// Its own match finder (4 candidates, last distance), one literal
    /// code per block; sizes about google/brotli quality 4.
    fast,
    /// 32 candidates; literal context modelling (UTF8 / LSB6 modes).
    default,
    /// 256 candidates, context modelling as `.default`. For content
    /// compressed once and served many times.
    best,
    /// A shortest-path parse of every block priced from the block's own
    /// statistics, over 256 candidates. For content compressed once and
    /// served many times; several times `.best`'s time.
    max,

    /// log2 of all bucket slots together, the match finder's table.
    fn slotsLog(e: Effort) u5 {
        return switch (e) {
            .fast => unreachable, // `FastMatcher`
            .default => 19,
            .best => 20,
            .max => 22,
        };
    }

    fn depth(e: Effort) u32 {
        return switch (e) {
            .fast => unreachable, // `FastMatcher`
            .default => 32,
            .best => 256,
            .max => 256,
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
    /// same (`Options.dictionary`). Its positions are searched like the
    /// input's (the table is sized for both).
    dictionary: []const u8 = &.{},

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
    const wbits: u5 = opts.window_bits orelse if (input.len > 65520) 21 else 16;
    var core = try Core.init(gpa, opts.effort, opts.block_size, wbits, input.len + opts.dictionary.len);
    defer core.deinit();
    const data = try withDictionary(gpa, input, opts.dictionary);
    defer if (data.ptr != input.ptr) gpa.free(data);
    try oneShot(&core, data, opts.dictionary.len, opts.block_size);
    return core.w.buf.toOwnedSlice(gpa);
}

/// `dict ++ input` (the match finder's one history), or `input` itself.
fn withDictionary(gpa: std.mem.Allocator, input: []const u8, dict: []const u8) std.mem.Allocator.Error![]const u8 {
    if (dict.len == 0) return input;
    const data = try gpa.alloc(u8, dict.len + input.len);
    @memcpy(data[0..dict.len], dict);
    @memcpy(data[dict.len..], input);
    return data;
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
    const wbits: u5 = opts.window_bits orelse if (input.len > 65520) 21 else 16;
    var core = try Core.init(gpa, opts.effort, opts.block_size, wbits, input.len + opts.dictionary.len);
    defer core.deinit();
    core.w.buf = .initBuffer(out);
    core.w.fixed = true;
    const data = try withDictionary(gpa, input, opts.dictionary);
    defer if (data.ptr != input.ptr) gpa.free(data);
    oneShot(&core, data, opts.dictionary.len, opts.block_size) catch |e| return if (core.w.overflowed) error.OutputTooLarge else e;
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

/// The header, every block of `data[dict_len..]` (`data[0..dict_len]` is
/// a raw prefix dictionary), the end.
fn oneShot(core: *Core, data: []const u8, dict_len: usize, block_size: usize) std.mem.Allocator.Error!void {
    core.setData(data);
    core.loadDictionary(dict_len);
    try core.writeHeader();
    var off: usize = dict_len;
    while (off < data.len) {
        const end = off + @min(data.len - off, block_size);
        try core.compressBlock(off, end, end == data.len);
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
    matcher: union { deep: Matcher, fast: FastMatcher },
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
    /// `.max`: the parses of a block (`buildCommandsOptimal`), and the writer
    /// that sizes each.
    parses: [max_parses]std.ArrayListUnmanaged(Cmd) = @splat(.empty),
    trial: BitWriter,
    /// `.max`: the static dictionary's index (`DictSearch`), made on first use.
    dict_search: ?DictSearch = null,
    /// The decoder's last four distances after the blocks so far.
    ring: DistRing = .{},
    /// The last block written was ISLAST.
    emitted_last: bool = false,
    /// `bucketLog` the tables were made with.
    table_log: u6,

    /// `size`: how much input the match finder's tables are sized for.
    pub fn init(gpa: std.mem.Allocator, effort: Effort, block_size: usize, wbits: u5, size: usize) std.mem.Allocator.Error!Core {
        std.debug.assert(block_size >= 1 and block_size <= compressed_block_size);
        std.debug.assert(wbits >= min_window_bits and wbits <= max_large_window_bits);
        return .{
            .gpa = gpa,
            .effort = effort,
            .block_size = block_size,
            .wbits = wbits,
            .matcher = if (effort == .fast)
                .{ .fast = try FastMatcher.init(gpa, size, fast_bucket_log_max) }
            else
                .{ .deep = try Matcher.init(gpa, size, effort.depth(), effort.slotsLog()) },
            .w = .{ .gpa = gpa },
            .alt = .{ .gpa = gpa },
            .scratch = .{ .gpa = gpa },
            .trial = .{ .gpa = gpa },
            .table_log = tableLog(effort, size),
        };
    }

    pub fn deinit(c: *Core) void {
        if (c.effort == .fast) c.matcher.fast.deinit(c.gpa) else c.matcher.deep.deinit(c.gpa);
        if (!c.w.fixed) c.w.buf.deinit(c.gpa);
        c.alt.buf.deinit(c.gpa);
        c.scratch.buf.deinit(c.gpa);
        c.cmds.deinit(c.gpa);
        for (&c.parses) |*l| l.deinit(c.gpa);
        if (c.dict_search) |*d| d.deinit(c.gpa);
        c.trial.buf.deinit(c.gpa);
        c.* = undefined;
    }

    pub fn prefix(c: *const Core) Prefix {
        return if (c.effort == .fast) c.matcher.fast.prefix else c.matcher.deep.prefix;
    }

    /// `data[0..len]` (after `setData`) is a raw prefix dictionary: its
    /// positions go into the match finder — those whose hashed bytes all lie
    /// inside it, so the tables do not depend on what follows.
    pub fn loadDictionary(c: *Core, len: usize) void {
        const x: Prefix = .{ .len = len };
        if (c.effort == .fast) c.matcher.fast.prefix = x else c.matcher.deep.prefix = x;
        var p: usize = 0;
        while (p + 8 <= len) : (p += 1) {
            if (c.effort == .fast) c.matcher.fast.insert(p) else c.matcher.deep.insert(p);
        }
    }

    /// The `bucketLog` `init` gives an effort's tables for `size`.
    pub fn tableLog(effort: Effort, size: usize) u6 {
        return if (effort == .fast) bucketLog(size, fast_bucket_log_max) else bucketLog(size, effort.slotsLog() - std.math.log2_int(u32, effort.depth()));
    }

    /// Ready for a new stream, as `init` leaves it (the tables kept).
    pub fn reset(c: *Core) void {
        if (c.effort == .fast) c.matcher.fast.reset() else c.matcher.deep.reset();
        if (c.effort == .fast) {
            c.matcher.fast.prefix = .{};
        } else c.matcher.deep.prefix = .{};
        c.data = &.{};
        c.w.buf.clearRetainingCapacity();
        c.w.acc = 0;
        c.w.cnt = 0;
        c.ring = .{};
        c.emitted_last = false;
    }

    /// `data` will lose its first `by` bytes (`setData` follows).
    pub fn shift(c: *Core, by: usize) void {
        if (c.effort == .fast) c.matcher.fast.shift(@intCast(by)) else c.matcher.deep.shift(@intCast(by));
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
        if (c.effort == .fast) c.matcher.fast.data = data else c.matcher.deep.data = data;
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
            .fast => if (c.prefix().len != 0)
                try buildCommandsFast(true, gpa, &c.matcher.fast, off, end, max_dist, c.ring, &c.cmds)
            else
                try buildCommandsFast(false, gpa, &c.matcher.fast, off, end, max_dist, c.ring, &c.cmds),
            .max => {
                const n_dist: usize = if (c.wbits > max_window_bits) dist_alphabet_large else dist_alphabet_size;
                if (c.prefix().len != 0) {
                    try buildCommandsOptimal(true, gpa, &c.matcher.deep, off, end, max_dist, c.ring, n_dist, null, &c.parses);
                } else {
                    // Built once per encoder, on its first such block.
                    if (c.dict_search == null) c.dict_search = try DictSearch.init(gpa);
                    try buildCommandsOptimal(false, gpa, &c.matcher.deep, off, end, max_dist, c.ring, n_dist, &c.dict_search.?, &c.parses);
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
            .default, .best => {
                c.matcher.deep.ring = c.ring;
                if (c.prefix().len != 0)
                    try buildCommands(4, true, gpa, &c.matcher.deep, off, end, max_dist, &c.cmds)
                else
                    try buildCommands(4, false, gpa, &c.matcher.deep, off, end, max_dist, &c.cmds);
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
        if (ok and w.bitPos() < store_bits) {
            c.ring = trial; // a stored block leaves the decoder's ring alone
            c.emitted_last = is_last;
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
        const x = c.prefix();
        const out = c.data[x.len..];
        const env: BlockEnv = .{ .reach = x.len + x.dropped, .large_window = c.wbits > max_window_bits, .dropped = x.dropped, .max_backward = (@as(usize, 1) << c.wbits) - 16 };
        const first = (try tryBlock(c.gpa, dst, out, off - x.len, end - x.len, c.cmds.items, is_last, &trial, c.effort, false, env)) orelse return false;
        // The context model was chosen on estimated bits. When it split the
        // literals, write the block once more with a single literal code and
        // keep whichever is really shorter (a flat, small alphabet is where
        // the estimate overfits: `alpha5_flat` came out 1.4 % larger with
        // contexts than without).
        // `writeCompressedBlock` prices that alternative on exact bits, so it
        // is written only when it wins — to `alt`, resumed at the same bit,
        // and spliced in. The real write still decides (`ctx_bits` below).
        if (first.ntrees > 1 and first.single_no_worse) {
            const ctx_bits = dst.bitPos() - dm.len * 8;
            c.alt.resumeAt(dm);
            var single_ring = c.ring;
            const single = try tryBlock(c.gpa, &c.alt, out, off - x.len, end - x.len, c.cmds.items, is_last, &single_ring, c.effort, true, env);
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
        inline for (.{ Effort.fast, .default, .best }) |effort| {
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
            const opts: CompressOptions = .{ .effort = .fast, .window_bits = wbits, .block_size = bs };
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
        const opts: CompressOptions = .{ .effort = .fast, .window_bits = wbits };
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
    const near = try compressWith(gpa, input, .{ .effort = .fast, .window_bits = 24 });
    defer gpa.free(near);
    try testing.expect(near.len > 2 * block);
}

// --- `.max`: shortest-path parse and static-dictionary words -----------------

fn expectMaxRoundTrip(input: []const u8, opts: CompressOptions, dopts: @import("decoder.zig").Options) ![]u8 {
    const gpa = testing.allocator;
    var o = opts;
    o.effort = .max;
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
    const best = try compressWith(gpa, alice, .{ .effort = .best });
    defer gpa.free(best);
    for ([_]CompressOptions{ .{}, .{ .window_bits = 16 }, .{ .window_bits = 12 }, .{ .block_size = 7_000 } }) |o| {
        const out = try expectMaxRoundTrip(alice, o, .{});
        defer gpa.free(out);
        if (o.window_bits == null and o.block_size == CompressOptions.default_block_size) try testing.expect(out.len < best.len);
    }
}

test "max: dictionary words with their transforms are used" {
    // Words of the static dictionary, spaced, cut, capitalised and in capitals:
    // without dictionary references this stays near its size as `.best`.
    const text = "international organization government university information. " ++
        "International Organization Government University Information, " ++
        "INTERNATIONAL ORGANIZATION GOVERNMENT UNIVERSITY INFORMATION; " ++
        "the international organization of the government of the university\n" ++
        "tomorrow yesterday however sometimes everything something nothing";
    const gpa = testing.allocator;
    const out = try expectMaxRoundTrip(text, .{}, .{});
    defer gpa.free(out);
    const best = try compressWith(gpa, text, .{ .effort = .best });
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
    // With a prefix dictionary words are never emitted.
    try testing.expectError(error.EncoderInvariant, checkWord(good, pos, .{ .reach = 10 }, "time"));
}
