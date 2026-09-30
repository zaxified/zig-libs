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
//!   the effort (`Effort`: 8 / 32 / 256 candidates), one lazy step.
//! - **Distance short codes and implicit distances**: the encoder mirrors the
//!   decoder's ring of the last four distances (`DistRing`) and names a
//!   distance by its short code (0..15, no extra bits) when it can; a copy at
//!   the last distance whose lengths fit uses an implicit-distance command
//!   and no distance symbol at all.
//! - **Literal context modelling** (not at `.fast`): per-context histograms
//!   for the UTF8 and LSB6 modes, clustered greedily by estimated bits into
//!   at most 16 codes, the cheaper mode kept — and then checked on real bits
//!   against a single literal code, keeping the shorter block.
//!
//! ## What it deliberately does not do
//!
//! - No block splitting (`NBLTYPES` is always 1), no static-dictionary
//!   references, no `NPOSTFIX`/`NDIRECT` tuning, no MSB6/SIGNED context modes
//!   (never the cheaper choice on the measured corpus), no optimal parse.
//!
//! The result: `alice29.txt` 51 467 bytes at `.default` (reference q5: 52 809,
//! q9: 51 054, q11: 46 487), 50 736 at `.best`; never worse than store mode by
//! more than the two-bit final-meta-block marker.
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
const BrotliError = @import("errors.zig").BrotliError;

// ---------------------------------------------------------------------------
// Tunables.

/// Maximum bytes per uncompressed meta-block (MLEN is a 24-bit field + 1).
const max_store_block = 1 << 24;
/// Bytes of input per compressed meta-block. Bigger amortises the ~100-300
/// byte prefix-code header better; smaller adapts to changing statistics.
const compressed_block_size = 1 << 20;

const chain_log_max = 20;
const hash_log_max = 17;
const min_match = 4;
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

    fn writeBits(self: *BitWriter, val: u32, n: u6) std.mem.Allocator.Error!void {
        const m: u64 = (@as(u64, 1) << n) - 1;
        self.acc |= (@as(u64, val) & m) << self.cnt;
        self.cnt += n;
        while (self.cnt >= 8) {
            try self.buf.append(self.gpa, @truncate(self.acc & 0xff));
            self.acc >>= 8;
            self.cnt -= 8;
        }
    }

    fn alignToByte(self: *BitWriter) std.mem.Allocator.Error!void {
        if (self.cnt != 0) {
            try self.buf.append(self.gpa, @truncate(self.acc & 0xff));
            self.acc = 0;
            self.cnt = 0;
        }
    }

    fn writeBytes(self: *BitWriter, bytes: []const u8) std.mem.Allocator.Error!void {
        try self.buf.appendSlice(self.gpa, bytes);
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

const DistCode = struct { offset: u32, nbits: u5 };

const dist_lut: [dist_alphabet_size]DistCode = blk: {
    var out: [dist_alphabet_size]DistCode = .{DistCode{ .offset = 0, .nbits = 0 }} ** dist_alphabet_size;
    var bits: u32 = 1;
    var half: u32 = 0;
    var i: usize = tables.num_distance_short_codes;
    while (i < dist_alphabet_size) {
        out[i] = .{ .offset = ((2 + half) << bits) - 4 + 1, .nbits = bits };
        i += 1;
        bits += half;
        half ^= 1;
    }
    break :blk out;
};

/// Smallest explicit distance code (>= 16) whose range contains `d`, or null
/// when `d` is outside the whole alphabet.
fn distanceCode(d: u32) ?struct { sym: u16, extra: u32, nbits: u5 } {
    var c: usize = tables.num_distance_short_codes;
    while (c < dist_alphabet_size) : (c += 1) {
        const e = dist_lut[c];
        if (d < e.offset) continue;
        const span: u64 = @as(u64, 1) << e.nbits;
        if (d - e.offset < span) return .{ .sym = @intCast(c), .extra = d - e.offset, .nbits = e.nbits };
    }
    return null;
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
        self.last = .{ d, self.last[0], self.last[1], self.last[2] };
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

/// Largest length code whose range contains `len`.
fn lengthCode(offsets: *const [24]u32, nbits: *const [24]u5, len: u32) ?struct { code: u5, extra: u32, nbits: u5 } {
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
/// A symbol with code length L occupies table indices `rev + k * 2^L`; the
/// smallest of those, `rev`, is exactly the L bits to write (the reader peeks
/// `table.bits` bits and indexes with them, so the first bit written is the
/// index's bit 0). Deriving the patterns from the table the *decoder* would
/// build removes any chance of the two disagreeing about canonical code
/// assignment — the format-level risk is anchored externally instead.
fn codeFromTable(gpa: std.mem.Allocator, table: *const huffman.Table, alphabet_size: u32) !Code {
    const bits = try gpa.alloc(u16, alphabet_size);
    errdefer gpa.free(bits);
    const len = try gpa.alloc(u8, alphabet_size);
    errdefer gpa.free(len);
    @memset(bits, 0);
    @memset(len, 0);

    const size = @as(usize, 1) << table.bits;
    for (table.entries[0..size], 0..) |e, i| {
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
        try writeSimpleCode(w, alphabet_size, vals[0..m], tree_select);
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
// Match finding: one hash chain over 4-byte hashes, one lazy step.

const Match = struct { len: u32, dist: u32, gain: f32 };

const Matcher = struct {
    /// Candidates walked per lookup (`Effort.chainDepth`).
    chain_depth: usize,
    /// Estimated bits a literal costs in the current block (its order-0
    /// entropy): what a match saves per byte it covers. Set per block.
    lit_cost: f32 = 8,
    head: []u32,
    prev: []u32,
    mask: usize,
    hash_shift: u5,
    data: []const u8,

    const empty: u32 = 0xffff_ffff;

    fn init(gpa: std.mem.Allocator, data: []const u8, chain_depth: usize) std.mem.Allocator.Error!Matcher {
        // Both tables are sized to the input: compressing a few hundred bytes
        // must not cost a fixed half-megabyte of zeroed hash table.
        var chain_log: u6 = 1;
        while (chain_log < chain_log_max and (@as(usize, 1) << chain_log) < data.len) chain_log += 1;
        var hash_log: u6 = 8;
        while (hash_log < hash_log_max and (@as(usize, 1) << hash_log) < data.len) hash_log += 1;

        const size = @as(usize, 1) << chain_log;
        const head = try gpa.alloc(u32, @as(usize, 1) << hash_log);
        errdefer gpa.free(head);
        const prev = try gpa.alloc(u32, size);
        @memset(head, empty);
        @memset(prev, empty);
        return .{
            .chain_depth = chain_depth,
            .head = head,
            .prev = prev,
            .mask = size - 1,
            .hash_shift = @intCast(32 - hash_log),
            .data = data,
        };
    }

    fn deinit(self: *Matcher, gpa: std.mem.Allocator) void {
        gpa.free(self.head);
        gpa.free(self.prev);
        self.* = undefined;
    }

    fn hash(self: *const Matcher, p: usize) usize {
        const v = std.mem.readInt(u32, self.data[p..][0..4], .little);
        return (v *% 0x1e35a7bd) >> self.hash_shift;
    }

    fn insert(self: *Matcher, p: usize) void {
        if (p + min_match > self.data.len) return;
        const h = self.hash(p);
        self.prev[p & self.mask] = self.head[h];
        self.head[h] = @intCast(p);
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
    fn find(self: *const Matcher, p: usize, max_dist: usize, limit: usize) ?Match {
        if (p + min_match > limit) return null;
        const max_len = @min(limit - p, max_match);
        var best_len: usize = 0;
        var best_dist: usize = 0;
        var best_gain: f32 = 0;
        var cand = self.head[self.hash(p)];
        var depth: usize = 0;
        while (cand != empty and depth < self.chain_depth) : (depth += 1) {
            const c: usize = cand;
            if (c >= p) break;
            const d = p - c;
            if (d > max_dist) break;
            // Cheap reject: a candidate that cannot beat `best_len` is skipped
            // before the byte-by-byte compare.
            if (best_len == 0 or self.data[c + best_len] == self.data[p + best_len]) {
                var l: usize = 0;
                while (l < max_len and self.data[c + l] == self.data[p + l]) l += 1;
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
            const next = self.prev[c & self.mask];
            if (next != empty and next >= c) break; // stale / cyclic
            cand = next;
        }
        if (best_len < min_match) return null;
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
    copy_len: u32,
    dist: u32,
};

/// Greedy + one-step-lazy parse of `input[start..end)`. Matches may reach back
/// before `start` (the decoder's history is the whole output) but never past
/// `end`, so the commands consume exactly `end - start` bytes.
fn buildCommands(
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

    // The block's order-0 entropy, as the price of a literal.
    var hist = [_]u32{0} ** 256;
    for (matcher.data[start..end]) |b| hist[b] += 1;
    var sum: f64 = 0;
    for (hist) |c| sum += nlog2n(c);
    const n: f64 = @floatFromInt(end - start);
    matcher.lit_cost = @floatCast(@max(1.0, (nlog2n(end - start) - sum) / n));

    while (p < end) {
        const m = pending orelse matcher.find(p, @min(max_dist, p), end);
        pending = null;
        if (m == null) {
            matcher.insert(p);
            p += 1;
            continue;
        }
        matcher.insert(p);
        if (p + 1 < end) {
            if (matcher.find(p + 1, @min(max_dist, p + 1), end)) |b| {
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
        var q = p + 1;
        while (q < p + len) : (q += 1) matcher.insert(q);
        p += len;
        lit_start = p;
    }

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
    if (n < nlog2n_table.len) return nlog2n_table[n];
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
        pos += c.insert_len + c.copy_len;
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
/// cheapest clustering over the UTF8 and LSB6 context modes. MSB6 and SIGNED
/// are not tried: over the whole measured corpus (text, UTF-16, small random
/// alphabets, binary) neither ever won, so emitting them would be a path the
/// reference decoder never checked from this side, for no measured gain.
fn chooseLiteralModel(gpa: std.mem.Allocator, input: []const u8, start: usize, cmds: []const Cmd, effort: Effort, out: *LiteralModel) std.mem.Allocator.Error!void {
    out.* = .{};
    var n_lits: u64 = 0;
    var pos = start;
    for (cmds) |c| {
        for (input[pos..][0..c.insert_len]) |b| out.counts[0][b] += 1;
        n_lits += c.insert_len;
        pos += c.insert_len + c.copy_len;
    }
    if (effort == .fast or n_lits < 256) return;
    // Near 8 bits a literal: no context will find structure a single code
    // misses (random or already-compressed bytes).
    if (histogramCost(&out.counts[0]) > 7.9 * @as(f64, @floatFromInt(n_lits))) return;

    const scratch = try gpa.create(ClusterScratch);
    defer gpa.destroy(scratch);
    const single = histogramCost(&out.counts[0]);
    var best_cost = single;
    var trial: LiteralModel = undefined;
    for ([_]u2{ 2, 0 }) |mode| {
        const c = clusterLiterals(input, start, cmds, mode, scratch, &trial);
        if (c < best_cost) {
            best_cost = c;
            out.* = trial;
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
) GiveUp!u8 {
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
    };
    const res = try gpa.alloc(Resolved, cmds.len);
    defer gpa.free(res);

    const cmd_counts = try gpa.alloc(u32, tables.num_command_symbols);
    defer gpa.free(cmd_counts);
    @memset(cmd_counts, 0);
    var dist_counts = [_]u32{0} ** dist_alphabet_size;

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
        const short: ?u16 = if (c.copy_len != 0) ring.shortCode(c.dist) else null;
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
        };
        if (c.copy_len != 0) {
            if (c.dist == 0 or c.dist > lit_pos + c.insert_len) return error.EncoderInvariant;
            ring.update(c.dist, short);
        }
        if (r.has_dist) {
            if (short) |code| {
                r.dist_sym = code;
            } else {
                const dc = distanceCode(c.dist) orelse return error.EncoderInvariant;
                r.dist_sym = dc.sym;
                r.dist_extra = dc.extra;
                r.dist_nbits = dc.nbits;
            }
            dist_counts[r.dist_sym] += 1;
        }
        res[i] = r;
        cmd_counts[sym] += 1;
        lit_pos += c.insert_len;
        covered += c.insert_len + c.copy_len;
        lit_pos += c.copy_len;
    }
    // MLEN must match the bytes the commands produce exactly, or the decoder
    // would run past the end of the meta-block.
    if (covered != n) return error.EncoderInvariant;

    const model = try gpa.create(LiteralModel);
    defer gpa.destroy(model);
    try chooseLiteralModel(gpa, input, start, cmds, if (single_literal_code) .fast else effort, model);
    // Every code needs at least one symbol even when unused.
    for (model.counts[0..model.ntrees]) |*h| {
        var any = false;
        for (h) |c| {
            if (c != 0) any = true;
        }
        if (!any) h[0] = 1;
    }

    // Every alphabet needs at least one symbol even when unused.
    var dist_any = false;
    for (dist_counts) |c| {
        if (c != 0) dist_any = true;
    }
    if (!dist_any) dist_counts[0] = 1;

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
    try writeContextMap(gpa, w, &model.map, model.ntrees);
    try w.writeBits(0, 1);

    var lit_codes: [max_literal_trees]Code = undefined;
    var built: usize = 0;
    defer for (lit_codes[0..built]) |*c| c.deinit(gpa);
    while (built < model.ntrees) : (built += 1) {
        lit_codes[built] = try buildAndWriteCode(gpa, w, &model.counts[built], tables.num_literal_symbols);
    }
    var cmd_code = try buildAndWriteCode(gpa, w, cmd_counts, tables.num_command_symbols);
    defer cmd_code.deinit(gpa);
    var dist_code = try buildAndWriteCode(gpa, w, &dist_counts, dist_alphabet_size);
    defer dist_code.deinit(gpa);

    // --- commands -----------------------------------------------------------
    lit_pos = start;
    for (cmds, res) |c, r| {
        try cmd_code.emit(w, r.sym);
        if (r.insert_nbits != 0) try w.writeBits(r.insert_extra, r.insert_nbits);
        if (r.copy_nbits != 0) try w.writeBits(r.copy_extra, r.copy_nbits);
        for (lit_pos..lit_pos + c.insert_len) |q| {
            const p1: u8 = if (q >= 1) input[q - 1] else 0;
            const p2: u8 = if (q >= 2) input[q - 2] else 0;
            try lit_codes[model.map[contextId(model.mode, p1, p2)]].emit(w, input[q]);
        }
        lit_pos += c.insert_len;
        if (r.has_dist) {
            try dist_code.emit(w, r.dist_sym);
            if (r.dist_nbits != 0) try w.writeBits(r.dist_extra, r.dist_nbits);
        }
        lit_pos += c.copy_len;
    }
    return model.ntrees;
}

/// `writeCompressedBlock`, with a give-up (not OOM) as null: the caller
/// stores the block instead. Returns the number of literal codes used.
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
) std.mem.Allocator.Error!?u8 {
    return writeCompressedBlock(gpa, w, input, start, end, cmds, is_last, ring, effort, single_literal_code) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
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
    /// Shallow match search (8 candidates), one literal code per block.
    fast,
    /// 32 candidates; literal context modelling (UTF8 / LSB6 modes).
    default,
    /// 256 candidates, context modelling as `.default`. For content
    /// compressed once and served many times.
    best,

    fn chainDepth(e: Effort) usize {
        return switch (e) {
            .fast => 8,
            .default => 32,
            .best => 256,
        };
    }
};

pub const CompressOptions = struct {
    effort: Effort = .default,
    /// Input bytes per meta-block (1..1 MiB). Each block gets its own codes:
    /// smaller blocks adapt to changing data but pay more headers.
    block_size: usize = compressed_block_size,
};

/// `compress` with options.
pub fn compressWith(gpa: std.mem.Allocator, input: []const u8, opts: CompressOptions) std.mem.Allocator.Error![]u8 {
    const block_size = opts.block_size;
    std.debug.assert(block_size >= 1 and block_size <= compressed_block_size);
    var w = BitWriter{ .gpa = gpa };
    errdefer w.buf.deinit(gpa);

    // Window bits: 16 unless the input can actually use a bigger one. Encoded
    // as a single 0 bit for 16, otherwise 1 + (wbits - 17) in three bits.
    const big_window = input.len > 65520;
    const wbits: u6 = if (big_window) 21 else 16;
    if (big_window) {
        try w.writeBits(1, 1);
        try w.writeBits(wbits - 17, 3);
    } else {
        try w.writeBits(0, 1);
    }
    const max_backward = (@as(usize, 1) << wbits) - 16;

    var matcher = try Matcher.init(gpa, input, opts.effort.chainDepth());
    defer matcher.deinit(gpa);
    const max_dist = @min(max_backward, matcher.mask);

    var cmds: std.ArrayListUnmanaged(Cmd) = .empty;
    defer cmds.deinit(gpa);

    var emitted_last = false;
    var ring: DistRing = .{};
    var off: usize = 0;
    while (off < input.len) {
        const n = @min(input.len - off, block_size);
        const end = off + n;
        const is_last = end == input.len;

        cmds.clearRetainingCapacity();
        try buildCommands(gpa, &matcher, off, end, max_dist, &cmds);

        const m = w.mark();
        const before = w.bitPos();
        const store_bits = storeCostBits(before, n);
        var kept = false;
        var trial = ring;
        const first = try tryBlock(gpa, &w, input, off, end, cmds.items, is_last, &trial, opts.effort, false);
        var ok = first != null;
        // The context model was chosen on estimated bits. When it split the
        // literals, write the block once more with a single literal code and
        // keep whichever is really shorter (a flat, small alphabet is where
        // the estimate overfits: `alpha5_flat` came out 1.4 % larger with
        // contexts than without).
        if (first != null and first.? > 1) {
            const ctx_end = w.bitPos();
            w.rollback(m);
            var single_ring = ring;
            const single = try tryBlock(gpa, &w, input, off, end, cmds.items, is_last, &single_ring, opts.effort, true);
            if (single == null or ctx_end < w.bitPos()) {
                w.rollback(m);
                trial = ring;
                ok = (try tryBlock(gpa, &w, input, off, end, cmds.items, is_last, &trial, opts.effort, false)) != null;
            } else {
                trial = single_ring;
            }
        }
        kept = ok and w.bitPos() < store_bits;
        if (kept) {
            ring = trial; // a stored block leaves the decoder's ring alone
            emitted_last = is_last;
        } else {
            w.rollback(m);
            try writeStoreBlock(&w, input[off..end]);
            emitted_last = false;
        }
        off = end;
    }

    if (!emitted_last) {
        // Final empty meta-block: ISLAST = 1, ISLASTEMPTY = 1.
        try w.writeBits(1, 1);
        try w.writeBits(1, 1);
    }
    try w.alignToByte();

    return w.buf.toOwnedSlice(gpa);
}

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
        const c = distanceCode(d) orelse return error.NoDistanceCode;
        try testing.expect(c.sym >= tables.num_distance_short_codes);
        try testing.expect(c.sym < dist_alphabet_size);
        try testing.expectEqual(d, dist_lut[c.sym].offset + c.extra);
        try testing.expect(c.extra < @as(u64, 1) << c.nbits);
    }
    // Distance 0 is the "unused" slot in the alphabet, never a real distance.
    try testing.expect(distanceCode(0) == null);
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
