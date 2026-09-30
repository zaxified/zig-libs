// SPDX-License-Identifier: MIT
//! Pure-Zig Brotli decompressor (RFC 7932). Uses the growing output buffer as
//! flat LZ77 history; static-dictionary references resolve against the embedded
//! RFC 7932 Appendix A/B tables. Malformed input always yields a typed error.

const std = @import("std");
const BitReader = @import("bitreader.zig").BitReader;
const huffman = @import("huffman.zig");
const Table = huffman.Table;
const tables = @import("tables.zig");
const dict = @import("dictionary.zig");
const transforms = @import("transforms.zig");
const errors = @import("errors.zig");

pub const BrotliError = errors.BrotliError;

pub const Options = struct {
    /// Hard cap on decompressed size (DoS guard). Default 256 MiB. This
    /// alone is an absolute-only bound: at the default, a few-KB `br` body
    /// can cost up to 256 MiB of RSS regardless of its own size, which is
    /// the wrong default for decompressing an untrusted, attacker-sized
    /// body (wave-2 audit finding `brotli` F3). `decompress` combines it
    /// with `max_ratio`/`min_output_floor` below — see `effectiveCap`.
    max_output: usize = 256 * 1024 * 1024,
    /// Output-to-input expansion ratio allowed once `min_output_floor` is
    /// exceeded (see `effectiveCap`). 10000x is deliberately generous: this
    /// decoder's own test corpus legitimately hits ~20000x on a run of
    /// zeros (13 bytes -> 256 KiB, `testdata/zeros.compressed`), which is
    /// why that case is rescued by the floor rather than the ratio — the
    /// ratio bound exists to catch a *few-KB* hostile body inflating all
    /// the way to the absolute cap, not to bound legitimately
    /// highly-compressible small payloads.
    max_ratio: usize = 10000,
    /// Below this absolute output size, the ratio bound above does not
    /// apply at all: a decompressed size this small is not a meaningful
    /// memory-exhaustion risk on its own, whatever the input was.
    ///
    /// `max_ratio`/`min_output_floor` are deliberately independent of
    /// `max_output`: raising `max_output` alone does not also waive the
    /// ratio policy (see `effectiveCap`) -- a caller who wants to opt out
    /// of ratio-based rejection for a specific trusted source must raise
    /// this floor (or `max_ratio`) explicitly, not just the absolute cap.
    min_output_floor: usize = 1024 * 1024,
};

/// The output cap actually enforced for a stream of `input_len` bytes:
/// the smaller of the absolute `max_output` and a ratio bound relative to
/// `input_len`, but the ratio bound never drops below `min_output_floor`.
pub fn effectiveCap(options: Options, input_len: usize) usize {
    const ratio_bound = input_len *| options.max_ratio;
    const bounded = @max(options.min_output_floor, ratio_bound);
    return @min(options.max_output, bounded);
}

const block_size_cap: u32 = 1 << 24;

const MetaHeader = struct {
    is_last: bool,
    is_uncompressed: bool,
    is_metadata: bool,
    mlen: i64, // decoded length (uncompressed/compressed) or metadata skip length
};

/// The decoder over an output `Sink` — `ListSink` (one-shot: the whole output
/// is the window) or `RingSink` (streaming: a window-sized ring written out
/// to a `std.Io.Writer`). What a sink provides: `pos` (bytes produced),
/// `back(d)` (the byte `d` back, 1 ≤ d ≤ what the window holds), `reserve(n)`
/// (the output cap; `reserveStored` for an uncompressed meta-block),
/// `put`/`putSlice`, `readAligned` (an uncompressed meta-block straight from
/// the bit reader), `setWindow` and `endMetablock`.
fn DecoderOf(comptime Sink: type) type {
    return struct {
        const Self = @This();
        const Error = BrotliError || Sink.WriteError;

        /// Per-meta-block scratch (prefix codes, context maps, the distance
        /// table): reset at the start of every meta-block, so a long stream's
        /// tables do not pile up — the streaming decoder's memory stays the
        /// window plus one meta-block's tables, whatever the stream length.
        arena_state: *std.heap.ArenaAllocator,
        arena: std.mem.Allocator,
        br: *BitReader,
        out: *Sink,

        wbits: u6 = 0,
        max_backward: usize = 0,
        dist_rb: [4]i32 = .{ 16, 15, 11, 4 },
        dist_rb_idx: u32 = 0,

        // Per-metablock state (reset each metablock).
        num_block_types: [3]u32 = .{ 1, 1, 1 },
        block_length: [3]u32 = .{ block_size_cap, block_size_cap, block_size_cap },
        block_type_rb: [3][2]u32 = .{ .{ 1, 0 }, .{ 1, 0 }, .{ 1, 0 } },
        type_tree: [3]?Table = .{ null, null, null },
        len_tree: [3]?Table = .{ null, null, null },
        npostfix: u32 = 0,
        ndirect: u32 = 0,
        context_modes: []u8 = &.{},
        context_map: []u8 = &.{},
        num_literal_htrees: u32 = 1,
        dist_context_map: []u8 = &.{},
        num_dist_htrees: u32 = 1,
        literal_group: []Table = &.{},
        command_group: []Table = &.{},
        distance_group: []Table = &.{},
        dist_extra_bits: []u8 = &.{},
        dist_offset: []u32 = &.{},
        trivial_literal: []bool = &.{},

        // Current decoding cursors.
        context_map_slice: []u8 = &.{},
        literal_htree: *const Table = undefined,
        context_lookup: []const u8 = &.{},
        trivial_literal_context: bool = false,
        htree_command: *const Table = undefined,
        dist_context_map_slice: []u8 = &.{},
        dist_htree_index: u32 = 0,
        last_distance_context: u32 = 0,

        fn appendByte(self: *Self, b: u8) Error!void {
            try self.out.reserve(1, self.br);
            try self.out.put(b);
        }

        fn ensureRoom(self: *Self, n: usize) Error!void {
            try self.out.reserve(n, self.br);
        }

        // --- variable-length uint8 (0..255) -----------------------------------
        fn decodeVarLenUint8(self: *Self) Error!u32 {
            if (try self.br.takeBits(1) == 0) return 0;
            const n = try self.br.takeBits(3);
            if (n == 0) return 1;
            const extra = try self.br.takeBits(n);
            return (@as(u32, 1) << @intCast(n)) + extra;
        }

        // --- meta-block length header -----------------------------------------
        fn decodeMetaBlockLength(self: *Self) Error!MetaHeader {
            var h = MetaHeader{ .is_last = false, .is_uncompressed = false, .is_metadata = false, .mlen = 0 };
            h.is_last = (try self.br.takeBits(1)) != 0;
            if (h.is_last) {
                if ((try self.br.takeBits(1)) != 0) return h; // ISLASTEMPTY
            }
            const nb = try self.br.takeBits(2);
            if (nb == 3) {
                // Metadata block.
                h.is_metadata = true;
                if ((try self.br.takeBits(1)) != 0) return error.ReservedBitSet;
                const skip_bytes = try self.br.takeBits(2);
                if (skip_bytes == 0) return h; // mlen 0
                var mlen: i64 = 0;
                var i: u32 = 0;
                while (i < skip_bytes) : (i += 1) {
                    const bits = try self.br.takeBits(8);
                    if (i + 1 == skip_bytes and skip_bytes > 1 and bits == 0) return error.InvalidLength;
                    mlen |= @as(i64, bits) << @intCast(i * 8);
                }
                h.mlen = mlen + 1;
                return h;
            }
            const size_nibbles = nb + 4;
            var mlen: i64 = 0;
            var i: u32 = 0;
            while (i < size_nibbles) : (i += 1) {
                const bits = try self.br.takeBits(4);
                if (i + 1 == size_nibbles and size_nibbles > 4 and bits == 0) return error.InvalidLength;
                mlen |= @as(i64, bits) << @intCast(i * 4);
            }
            if (!h.is_last) {
                h.is_uncompressed = (try self.br.takeBits(1)) != 0;
            }
            h.mlen = mlen + 1;
            return h;
        }

        // --- reading a Huffman code (simple or complex) -----------------------
        fn readHuffmanCode(self: *Self, alphabet_size: u32) Error!Table {
            const kind = try self.br.takeBits(2);
            if (kind == 1) {
                // Simple prefix code.
                const max_bits = huffman.symbolBits(alphabet_size - 1);
                const nsym_sel = try self.br.takeBits(2); // 0..3
                const count = nsym_sel + 1;
                var vals: [4]u16 = undefined;
                var i: u32 = 0;
                while (i < count) : (i += 1) {
                    const v = try self.br.takeBits(max_bits);
                    if (v >= alphabet_size) return error.InvalidHuffman;
                    vals[i] = @intCast(v);
                }
                // Distinctness check.
                var a: u32 = 0;
                while (a < count) : (a += 1) {
                    var b: u32 = a + 1;
                    while (b < count) : (b += 1) {
                        if (vals[a] == vals[b]) return error.DuplicateSimpleSymbol;
                    }
                }
                var num_symbols: u8 = @intCast(nsym_sel);
                if (nsym_sel == 3) num_symbols += @intCast(try self.br.takeBits(1));
                return huffman.buildSimple(self.arena, num_symbols, vals[0..count]);
            }
            return self.readComplexHuffman(alphabet_size, kind);
        }

        fn readComplexHuffman(self: *Self, alphabet_size: u32, hskip: u32) Error!Table {
            var cl_lengths = [_]u8{0} ** tables.code_length_codes;
            var space: i32 = 32;
            var num_codes: u32 = 0;
            var i: u32 = hskip;
            while (i < tables.code_length_codes) : (i += 1) {
                const idx = tables.code_length_code_order[i];
                const b4 = self.br.peekBits(4);
                const plen = tables.code_length_prefix_length[b4];
                _ = try self.br.takeBits(plen); // TruncatedInput when fewer bits remain
                const v = tables.code_length_prefix_value[b4];
                cl_lengths[idx] = v;
                if (v != 0) {
                    space -= @as(i32, 32) >> @intCast(v);
                    num_codes += 1;
                    if (space <= 0) break;
                }
            }
            if (!(num_codes == 1 or space == 0)) return error.InvalidHuffman;

            var cl_table = try huffman.buildComplex(self.arena, &cl_lengths);
            defer cl_table.deinit(self.arena);

            // Decode the alphabet's per-symbol code lengths.
            const lengths = try self.arena.alloc(u8, alphabet_size);
            @memset(lengths, 0);
            var symbol: u32 = 0;
            var prev_code_len: u32 = tables.initial_repeated_code_length;
            var repeat: u32 = 0;
            var repeat_code_len: u32 = 0;
            var space2: i32 = 32768;
            while (symbol < alphabet_size and space2 > 0) {
                const code_len = try self.br.readSymbol(&cl_table);
                if (code_len < 16) {
                    repeat = 0;
                    if (code_len != 0) {
                        lengths[symbol] = @intCast(code_len);
                        prev_code_len = code_len;
                        space2 -= @as(i32, 32768) >> @intCast(code_len);
                    }
                    symbol += 1;
                } else {
                    const extra_bits: u32 = if (code_len == 16) 2 else 3;
                    const repeat_delta = try self.br.takeBits(extra_bits);
                    const new_len: u32 = if (code_len == 16) prev_code_len else 0;
                    if (repeat_code_len != new_len) {
                        repeat = 0;
                        repeat_code_len = new_len;
                    }
                    const old_repeat = repeat;
                    if (repeat > 0) repeat = (repeat - 2) << @intCast(extra_bits);
                    repeat += repeat_delta + 3;
                    const actual = repeat - old_repeat;
                    if (symbol + actual > alphabet_size) return error.InvalidHuffman;
                    if (repeat_code_len != 0) {
                        var j: u32 = 0;
                        while (j < actual) : (j += 1) {
                            lengths[symbol] = @intCast(repeat_code_len);
                            symbol += 1;
                        }
                        space2 -= @as(i32, @intCast(actual)) << @intCast(15 - repeat_code_len);
                    } else {
                        symbol += actual;
                    }
                }
            }
            if (space2 != 0) return error.InvalidHuffman;
            return huffman.buildComplex(self.arena, lengths);
        }

        fn readTreeGroup(self: *Self, alphabet_size: u32, count: u32) Error![]Table {
            const group = try self.arena.alloc(Table, count);
            var i: u32 = 0;
            while (i < count) : (i += 1) group[i] = try self.readHuffmanCode(alphabet_size);
            return group;
        }

        // --- context map ------------------------------------------------------
        fn decodeContextMap(self: *Self, size: u32, num_htrees_out: *u32) Error![]u8 {
            const num_htrees = (try self.decodeVarLenUint8()) + 1;
            num_htrees_out.* = num_htrees;
            const map = try self.arena.alloc(u8, size);
            @memset(map, 0);
            if (num_htrees <= 1) return map;

            var max_run: u32 = 0;
            const bits5 = self.br.peekBits(5);
            if ((bits5 & 1) != 0) {
                max_run = (bits5 >> 1) + 1;
                _ = try self.br.takeBits(5);
            } else {
                _ = try self.br.takeBits(1);
            }
            var cmap_table = try self.readHuffmanCode(num_htrees + max_run);
            defer cmap_table.deinit(self.arena);

            var i: u32 = 0;
            while (i < size) {
                const code = try self.br.readSymbol(&cmap_table);
                if (code == 0) {
                    map[i] = 0;
                    i += 1;
                } else if (code > max_run) {
                    map[i] = @intCast(code - max_run);
                    i += 1;
                } else {
                    var reps = (try self.br.takeBits(code)) + (@as(u32, 1) << @intCast(code));
                    if (i + reps > size) return error.InvalidContextMap;
                    while (reps > 0) : (reps -= 1) {
                        map[i] = 0;
                        i += 1;
                    }
                }
            }
            if ((try self.br.takeBits(1)) != 0) inverseMoveToFront(map);
            return map;
        }

        // --- distance lookup table --------------------------------------------
        fn calculateDistanceLut(self: *Self, alphabet_size: u32) Error!void {
            self.dist_extra_bits = try self.arena.alloc(u8, alphabet_size);
            self.dist_offset = try self.arena.alloc(u32, alphabet_size);
            @memset(self.dist_extra_bits, 0);
            @memset(self.dist_offset, 0);
            const npostfix = self.npostfix;
            const ndirect = self.ndirect;
            const postfix: u32 = @as(u32, 1) << @intCast(npostfix);
            var bits: u32 = 1;
            var half: u32 = 0;
            var i: u32 = tables.num_distance_short_codes;
            var j: u32 = 0;
            while (j < ndirect) : (j += 1) {
                self.dist_extra_bits[i] = 0;
                self.dist_offset[i] = j + 1;
                i += 1;
            }
            while (i < alphabet_size) {
                const base = ndirect + ((((2 + half) << @intCast(bits)) - 4) << @intCast(npostfix)) + 1;
                j = 0;
                while (j < postfix) : (j += 1) {
                    self.dist_extra_bits[i] = @intCast(bits);
                    self.dist_offset[i] = base + j;
                    i += 1;
                }
                bits += half;
                half ^= 1;
            }
        }

        // --- block-type switching ---------------------------------------------
        fn decodeBlockTypeAndLength(self: *Self, tt: usize) Error!void {
            const max_bt = self.num_block_types[tt];
            if (self.type_tree[tt] == null or self.len_tree[tt] == null) return error.InvalidHuffman;
            const tt_tree = &self.type_tree[tt].?;
            const ln_tree = &self.len_tree[tt].?;
            const block_type = try self.br.readSymbol(tt_tree);
            self.block_length[tt] = try self.readBlockLength(ln_tree);
            const rb = &self.block_type_rb[tt];
            var bt: u32 = undefined;
            if (block_type == 1) {
                bt = rb[1] + 1;
            } else if (block_type == 0) {
                bt = rb[0];
            } else {
                bt = block_type - 2;
            }
            if (bt >= max_bt) bt -= max_bt;
            rb[0] = rb[1];
            rb[1] = bt;
        }

        fn readBlockLength(self: *Self, ln_tree: *const Table) Error!u32 {
            const code = try self.br.readSymbol(ln_tree);
            if (code >= tables.num_block_len_symbols) return error.InvalidHuffman;
            const range = tables.block_length_ranges[code];
            return range.offset + try self.br.takeBits(range.nbits);
        }

        fn prepareLiteralDecoding(self: *Self) void {
            const block_type = self.block_type_rb[0][1];
            self.context_map_slice = self.context_map[block_type * 64 ..][0..64];
            self.trivial_literal_context = self.trivial_literal[block_type];
            self.literal_htree = &self.literal_group[self.context_map_slice[0]];
            const mode = self.context_modes[block_type] & 3;
            self.context_lookup = tables.context_lookup[@as(usize, mode) * 512 ..][0..512];
        }

        fn detectTrivialLiteralBlockTypes(self: *Self) Error!void {
            self.trivial_literal = try self.arena.alloc(bool, self.num_block_types[0]);
            var t: u32 = 0;
            while (t < self.num_block_types[0]) : (t += 1) {
                const offset = t * 64;
                const sample = self.context_map[offset];
                var triv = true;
                var k: u32 = 0;
                while (k < 64) : (k += 1) {
                    if (self.context_map[offset + k] != sample) {
                        triv = false;
                        break;
                    }
                }
                self.trivial_literal[t] = triv;
            }
        }

        // --- distance from the recent-distances ring buffer -------------------
        fn takeDistanceFromRingBuffer(self: *Self, code: u32) i32 {
            var distance_context: u32 = 0;
            var result: i32 = undefined;
            if (code <= 3) {
                distance_context = @as(u32, 1) >> @intCast(code); // code 0 -> 1, else 0
                const offset: i32 = @as(i32, @intCast(code)) - 3;
                const idx = self.dist_rb_idx -% @as(u32, @bitCast(offset));
                result = self.dist_rb[idx & 3];
                self.dist_rb_idx -%= distance_context;
            } else {
                var index_delta: i32 = 3;
                var base: u32 = undefined;
                if (code < 10) {
                    base = code - 4;
                } else {
                    base = code - 10;
                    index_delta = 2;
                }
                const packed_deltas: u32 = 0x605142;
                const delta: i32 = @as(i32, @intCast((packed_deltas >> @as(u5, @intCast(4 * base))) & 0xF)) - 3;
                const idx = self.dist_rb_idx +% @as(u32, @bitCast(index_delta));
                const r: i64 = @as(i64, self.dist_rb[idx & 3]) + delta;
                result = if (r <= 0 or r > tables.max_allowed_distance) 0x7FFFFFFF else @intCast(r);
            }
            self.last_distance_context = distance_context;
            return result;
        }

        fn readDistance(self: *Self) Error!i32 {
            const dtree = &self.distance_group[self.dist_htree_index];
            const code = try self.br.readSymbol(dtree);
            self.block_length[2] -= 1;
            self.last_distance_context = 0;
            if ((code & ~@as(u16, 0xf)) == 0) {
                return self.takeDistanceFromRingBuffer(code);
            }
            if (code >= self.dist_offset.len) return error.InvalidDistance;
            const nbits = self.dist_extra_bits[code];
            const bits = try self.br.takeBits(nbits);
            const dv: u64 = @as(u64, self.dist_offset[code]) + (@as(u64, bits) << @intCast(self.npostfix));
            return if (dv > tables.max_allowed_distance) 0x7FFFFFFF else @intCast(dv);
        }

        // --- one compressed meta-block ----------------------------------------
        fn decodeCompressedMetablock(self: *Self, mlen: i64) Error!void {
            // Read the three (num_block_types, type tree, len tree, block length) sets.
            var tt: usize = 0;
            while (tt < 3) : (tt += 1) {
                self.num_block_types[tt] = (try self.decodeVarLenUint8()) + 1;
                if (self.num_block_types[tt] >= 2) {
                    self.type_tree[tt] = try self.readHuffmanCode(self.num_block_types[tt] + 2);
                    self.len_tree[tt] = try self.readHuffmanCode(tables.num_block_len_symbols);
                    self.block_length[tt] = try self.readBlockLength(&self.len_tree[tt].?);
                }
            }

            // NPOSTFIX / NDIRECT.
            const bits6 = try self.br.takeBits(6);
            self.npostfix = bits6 & 3;
            self.ndirect = (bits6 >> 2) << @intCast(self.npostfix);

            // Context modes.
            self.context_modes = try self.arena.alloc(u8, self.num_block_types[0]);
            var m: u32 = 0;
            while (m < self.num_block_types[0]) : (m += 1) {
                self.context_modes[m] = @intCast(try self.br.takeBits(2));
            }

            // Context maps.
            self.context_map = try self.decodeContextMap(self.num_block_types[0] << tables.literal_context_bits, &self.num_literal_htrees);
            try self.detectTrivialLiteralBlockTypes();
            self.dist_context_map = try self.decodeContextMap(self.num_block_types[2] << tables.distance_context_bits, &self.num_dist_htrees);

            // Tree groups.
            const dist_alphabet_size = tables.distanceAlphabetSize(self.npostfix, self.ndirect, tables.max_distance_bits);
            self.literal_group = try self.readTreeGroup(tables.num_literal_symbols, self.num_literal_htrees);
            self.command_group = try self.readTreeGroup(tables.num_command_symbols, self.num_block_types[1]);
            self.distance_group = try self.readTreeGroup(dist_alphabet_size, self.num_dist_htrees);

            // Prepare cursors.
            self.prepareLiteralDecoding();
            self.dist_context_map_slice = self.dist_context_map[0..];
            self.htree_command = &self.command_group[0];
            try self.calculateDistanceLut(dist_alphabet_size);

            try self.runCommands(mlen);
        }

        fn runCommands(self: *Self, mlen_in: i64) Error!void {
            var mlen = mlen_in;
            while (mlen > 0) {
                // Command block switch.
                if (self.block_length[1] == 0) {
                    try self.decodeBlockTypeAndLength(1);
                    self.htree_command = &self.command_group[self.block_type_rb[1][1]];
                }
                const cmd = try self.br.readSymbol(self.htree_command);
                self.block_length[1] -= 1;
                if (cmd >= tables.num_command_symbols) return error.InvalidHuffman;
                const v = tables.cmd_lut[cmd];
                const insert_len: u32 = v.insert_len_offset + try self.br.takeBits(v.insert_len_extra_bits);
                const copy_len: u32 = v.copy_len_offset + try self.br.takeBits(v.copy_len_extra_bits);
                self.dist_htree_index = self.dist_context_map_slice[v.context];

                // Insert literals.
                var j: u32 = 0;
                try self.ensureRoom(insert_len);
                while (j < insert_len) : (j += 1) {
                    if (self.block_length[0] == 0) {
                        try self.decodeBlockTypeAndLength(0);
                        self.prepareLiteralDecoding();
                    }
                    var lit: u16 = undefined;
                    if (self.trivial_literal_context) {
                        lit = try self.br.readSymbol(self.literal_htree);
                    } else {
                        const len = self.out.pos();
                        const p1: u8 = if (len >= 1) self.out.back(1) else 0;
                        const p2: u8 = if (len >= 2) self.out.back(2) else 0;
                        const context = self.context_lookup[p1] | self.context_lookup[256 + @as(usize, p2)];
                        const hc = &self.literal_group[self.context_map_slice[context]];
                        lit = try self.br.readSymbol(hc);
                    }
                    try self.appendByte(@intCast(lit));
                    self.block_length[0] -= 1;
                }
                mlen -= insert_len;
                if (mlen <= 0) break;

                // Distance.
                var distance: i32 = undefined;
                if (v.distance_code >= 0) {
                    // Implicit (== 0): reuse last distance.
                    self.last_distance_context = 1;
                    self.dist_rb_idx -%= 1;
                    distance = self.dist_rb[self.dist_rb_idx & 3];
                } else {
                    if (self.block_length[2] == 0) {
                        try self.decodeBlockTypeAndLength(2);
                        self.dist_context_map_slice = self.dist_context_map[self.block_type_rb[2][1] * 4 ..][0..4];
                        // A distance block switch re-selects the htree for the
                        // command's current distance context (RFC 7932 / reference).
                        self.dist_htree_index = self.dist_context_map_slice[v.context];
                    }
                    distance = try self.readDistance();
                }

                const pos = self.out.pos();
                const max_distance: i64 = @min(@as(i64, @intCast(pos)), @as(i64, @intCast(self.max_backward)));
                const copy: usize = copy_len;

                if (@as(i64, distance) > max_distance) {
                    // Static-dictionary reference.
                    if (distance > tables.max_allowed_distance) return error.InvalidDistance;
                    if (copy < dict.min_word_length or copy > dict.max_word_length) return error.InvalidDictionary;
                    const shift = dict.size_bits_by_length[copy];
                    if (shift == 0) return error.InvalidDictionary;
                    const address: i64 = @as(i64, distance) - max_distance - 1;
                    const word_mask: i64 = (@as(i64, 1) << @intCast(shift)) - 1;
                    const word_idx: usize = @intCast(address & word_mask);
                    const transform_idx: i64 = address >> @intCast(shift);
                    self.dist_rb_idx +%= self.last_distance_context;
                    if (transform_idx < 0 or transform_idx >= transforms.num_transforms) return error.InvalidDictionary;
                    const woff = dict.offsets_by_length[copy] + word_idx * copy;
                    if (woff + copy > dict.data.len) return error.InvalidDictionary;
                    const word = dict.data[woff..][0..copy];
                    // `copy` is bounded to `dict.max_word_length` above, so this
                    // buffer, sized from the same tables, provably holds any
                    // transform output even under ReleaseFast (no magic constant).
                    var buf: [transforms.maxOutputLen(dict.max_word_length)]u8 = undefined;
                    var wlen: usize = undefined;
                    if (transform_idx == 0) {
                        @memcpy(buf[0..copy], word);
                        wlen = copy;
                    } else {
                        wlen = transforms.transformWord(&buf, word, copy, @intCast(transform_idx));
                        if (wlen == 0 and distance <= 120) return error.InvalidDictionary;
                    }
                    try self.ensureRoom(wlen);
                    try self.out.putSlice(buf[0..wlen]);
                    mlen -= @intCast(wlen);
                } else {
                    // Normal LZ77 backward copy.
                    if (distance <= 0) return error.InvalidDistance;
                    const d: usize = @intCast(distance);
                    if (d > pos) return error.InvalidDistance;
                    self.dist_rb[self.dist_rb_idx & 3] = distance;
                    self.dist_rb_idx +%= 1;
                    try self.ensureRoom(copy);
                    // `back(d)` moves with every byte put, so an overlapping copy
                    // (d < copy) repeats the pattern, as LZ77 requires.
                    var k: usize = 0;
                    while (k < copy) : (k += 1) try self.out.put(self.out.back(d));
                    mlen -= @intCast(copy);
                }
                if (mlen <= 0) break;
            }
        }

        fn resetMetablock(self: *Self) void {
            self.num_block_types = .{ 1, 1, 1 };
            self.block_length = .{ block_size_cap, block_size_cap, block_size_cap };
            self.block_type_rb = .{ .{ 1, 0 }, .{ 1, 0 }, .{ 1, 0 } };
            self.type_tree = .{ null, null, null };
            self.len_tree = .{ null, null, null };
            self.num_literal_htrees = 1;
            self.num_dist_htrees = 1;
        }

        fn run(self: *Self) Error!void {
            // Window bits.
            self.wbits = try decodeWindowBits(self.br);
            self.max_backward = (@as(usize, 1) << self.wbits) - 16;
            try self.out.setWindow(self.wbits);

            while (true) {
                // Nothing from the previous meta-block is read again: every
                // table and cursor is rebuilt before the next command.
                _ = self.arena_state.reset(.retain_capacity);
                self.resetMetablock();
                const h = try self.decodeMetaBlockLength();
                if (h.is_metadata or h.is_uncompressed) try self.br.jumpToByteBoundary();

                if (h.is_metadata) {
                    try self.br.skipAlignedBytes(@intCast(h.mlen));
                    if (h.is_last) break;
                    continue;
                }
                if (h.mlen == 0) {
                    if (h.is_last) break;
                    continue;
                }
                if (h.mlen > block_size_cap) return error.InvalidLength;

                if (h.is_uncompressed) {
                    const n: usize = @intCast(h.mlen);
                    try self.out.reserveStored(n, self.br);
                    try self.out.readAligned(self.br, n);
                } else {
                    try self.decodeCompressedMetablock(h.mlen);
                }
                try self.out.endMetablock();
                if (h.is_last) break;
            }
        }
    };
}

fn decodeWindowBits(br: *BitReader) BrotliError!u6 {
    if ((try br.takeBits(1)) == 0) return 16;
    const n = try br.takeBits(3);
    if (n != 0) return @intCast(17 + n);
    const n2 = try br.takeBits(3);
    if (n2 == 1) return error.InvalidWindowBits; // large-window not supported
    if (n2 != 0) return @intCast(8 + n2);
    return 17;
}

fn inverseMoveToFront(v: []u8) void {
    var mtf: [256]u8 = undefined;
    for (0..256) |i| mtf[i] = @intCast(i);
    for (v) |*x| {
        const idx = x.*;
        const value = mtf[idx];
        var j: usize = idx;
        while (j > 0) : (j -= 1) mtf[j] = mtf[j - 1];
        mtf[0] = value;
        x.* = value;
    }
}

/// One-shot output: the whole output is the window.
const ListSink = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayListUnmanaged(u8) = .empty,
    cap: usize,

    const WriteError = error{};

    fn pos(s: *const ListSink) usize {
        return s.list.items.len;
    }
    fn back(s: *const ListSink, d: usize) u8 {
        return s.list.items[s.list.items.len - d];
    }
    fn reserve(s: *ListSink, n: usize, _: *const BitReader) BrotliError!void {
        if (s.list.items.len + n > s.cap) return error.OutputTooLarge;
        try s.list.ensureUnusedCapacity(s.gpa, n);
    }
    fn reserveStored(s: *ListSink, n: usize, br: *const BitReader) BrotliError!void {
        return s.reserve(n, br);
    }
    fn put(s: *ListSink, b: u8) BrotliError!void {
        s.list.appendAssumeCapacity(b);
    }
    fn putSlice(s: *ListSink, bytes: []const u8) BrotliError!void {
        s.list.appendSliceAssumeCapacity(bytes);
    }
    fn readAligned(s: *ListSink, br: *BitReader, n: usize) BrotliError!void {
        const start = s.list.items.len;
        s.list.items.len += n;
        try br.readAlignedBytes(s.list.items[start..][0..n]);
    }
    fn setWindow(_: *ListSink, _: u6) BrotliError!void {}
    fn endMetablock(_: *ListSink) BrotliError!void {}
};

/// Decompress a complete Brotli stream. Caller owns the returned slice.
pub fn decompress(gpa: std.mem.Allocator, input: []const u8, options: Options) BrotliError![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var br = BitReader.init(input);
    var sink: ListSink = .{ .gpa = gpa, .cap = effectiveCap(options, input.len) };
    errdefer sink.list.deinit(gpa);

    var dec = DecoderOf(ListSink){
        .arena_state = &arena_state,
        .arena = arena_state.allocator(),
        .br = &br,
        .out = &sink,
    };
    try dec.run();

    return try sink.list.toOwnedSlice(gpa);
}

/// Streaming output: the last `1 << wbits` bytes in a ring (every backward
/// distance fits: `max_backward` is 16 less), written out to `w` whenever the
/// ring is full and at the end of every meta-block. Memory is at most the
/// window, whatever the output size — and no more than the output needs: the
/// ring starts at 64 KiB and doubles while the output is still shorter than
/// the window (before its first wrap the ring is linear, so growing it is a
/// plain copy). A 1 KiB body under a 4 MiB window costs 64 KiB, not 4 MiB.
const RingSink = struct {
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    options: Options,
    buf: []u8 = &.{},
    mask: usize = 0,
    /// What the ring may grow to: the window, or less under a small cap.
    limit: usize = 0,
    total: usize = 0,
    flushed: usize = 0,

    const initial_len: usize = 1 << 16;

    const WriteError = error{WriteFailed};
    const Error = BrotliError || WriteError;

    fn deinit(s: *RingSink) void {
        s.gpa.free(s.buf);
    }
    fn pos(s: *const RingSink) usize {
        return s.total;
    }
    fn back(s: *const RingSink, d: usize) u8 {
        return s.buf[(s.total - d) & s.mask];
    }
    /// The cap of `effectiveCap`, with the input consumed *so far* standing
    /// in for the input length a stream does not know: the ratio bound can
    /// only grow as input arrives, so an early refusal is never undone.
    fn reserve(s: *RingSink, n: usize, br: *const BitReader) Error!void {
        const cap = effectiveCap(s.options, std.math.cast(usize, br.consumedBytes()) orelse std.math.maxInt(usize));
        if (s.total + n > cap) return error.OutputTooLarge;
    }
    /// An uncompressed meta-block is copied 1:1 from input not read yet, so
    /// it counts as consumed: without that, a stored block larger than the
    /// ratio floor would be refused as a bomb before its bytes arrive.
    fn reserveStored(s: *RingSink, n: usize, br: *const BitReader) Error!void {
        const consumed = std.math.cast(usize, br.consumedBytes()) orelse std.math.maxInt(usize);
        const cap = effectiveCap(s.options, consumed +| n);
        if (s.total + n > cap) return error.OutputTooLarge;
    }
    /// Room for one more byte: grow while the ring has not wrapped yet,
    /// else write out what is still unwritten (the bytes about to be
    /// overwritten are then only needed as history, which the ring keeps
    /// for the whole window).
    fn makeRoom(s: *RingSink) Error!void {
        if (s.total == s.buf.len and s.buf.len < s.limit) {
            const new_len = @min(s.buf.len * 2, s.limit);
            s.buf = try s.gpa.realloc(s.buf, new_len);
            s.mask = new_len - 1;
        } else if (s.total - s.flushed == s.buf.len) {
            try s.flushAll();
        }
    }
    fn put(s: *RingSink, b: u8) Error!void {
        if (s.total - s.flushed == s.buf.len or s.total == s.buf.len) try s.makeRoom();
        s.buf[s.total & s.mask] = b;
        s.total += 1;
    }
    fn putSlice(s: *RingSink, bytes: []const u8) Error!void {
        for (bytes) |b| try s.put(b);
    }
    fn readAligned(s: *RingSink, br: *BitReader, n: usize) Error!void {
        var rem = n;
        while (rem > 0) {
            if (s.total - s.flushed == s.buf.len or s.total == s.buf.len) try s.makeRoom();
            const at = s.total & s.mask;
            // Contiguous, and not over bytes still to be written out.
            const k = @min(rem, s.buf.len - at, s.buf.len - (s.total - s.flushed));
            try br.readAlignedBytes(s.buf[at..][0..k]);
            s.total += k;
            rem -= k;
        }
    }
    /// The ring's limit: the window, or less when the output cap is smaller
    /// (then nothing ever wraps, and a distance past what was produced is
    /// refused before it is read). It starts small; see `makeRoom`.
    fn setWindow(s: *RingSink, wbits: u6) Error!void {
        const window = @as(usize, 1) << wbits;
        const cap_pow2 = std.math.ceilPowerOfTwo(usize, @max(s.options.max_output, 1)) catch window;
        s.limit = @min(window, cap_pow2);
        const len = @min(s.limit, initial_len);
        s.buf = try s.gpa.alloc(u8, len);
        s.mask = len - 1;
    }
    fn endMetablock(s: *RingSink) Error!void {
        try s.flushAll();
    }
    fn flushAll(s: *RingSink) Error!void {
        while (s.flushed < s.total) {
            const at = s.flushed & s.mask;
            const k = @min(s.total - s.flushed, s.buf.len - at);
            try s.w.writeAll(s.buf[at..][0..k]);
            s.flushed += k;
        }
    }
};

/// Everything `decompressStream` can fail with: the format errors of
/// `decompress`, plus the two ends' own failures.
pub const StreamError = BrotliError || error{ ReadFailed, WriteFailed };

/// Decompress one Brotli stream from `in` to `out`, holding only the window
/// (≤ 16 MiB, `1 << WBITS`) and the decoding tables — never the whole output.
/// Output reaches `out` at the end of every meta-block and whenever the window
/// fills; `out` is flushed at the end. Returns the number of bytes written.
///
/// `in` must have a non-empty buffer. Up to 8 bytes after the stream may be
/// consumed from it (the bit reader reads ahead), so a Brotli stream followed
/// by other data on the same reader is not supported. `options` is enforced
/// as in `decompress`, but the ratio bound is measured against the input
/// consumed *so far* (the stream's length is unknown): a stream whose output
/// runs ahead of its input by more than `max_ratio` past `min_output_floor`
/// at any point is refused, even if `decompress` would have accepted the
/// whole body. An uncompressed meta-block counts its own bytes as input.
/// A `ReadFailed` from `in` is reported as such, not as `TruncatedInput`.
pub fn decompressStream(gpa: std.mem.Allocator, in: *std.Io.Reader, out: *std.Io.Writer, options: Options) StreamError!u64 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var br = BitReader.initStream(in);
    var sink: RingSink = .{ .gpa = gpa, .w = out, .options = options };
    defer sink.deinit();

    var dec = DecoderOf(RingSink){
        .arena_state = &arena_state,
        .arena = arena_state.allocator(),
        .br = &br,
        .out = &sink,
    };
    dec.run() catch |err| {
        if (err == error.TruncatedInput and br.read_failed) return error.ReadFailed;
        return err;
    };
    br.finish();
    try sink.flushAll();
    try out.flush();
    return sink.total;
}
