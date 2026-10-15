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
const shared = @import("shared_dictionary.zig");
pub const SharedDictionary = shared.SharedDictionary;

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
    /// A raw prefix dictionary (RFC 9841 §3.2; what RFC 9842 `dcb` uses):
    /// bytes a copy may reach as if they came just before the window. Must
    /// be the encoder's exactly. Not counted as output.
    dictionary: []const u8 = &.{},
    /// Accept large-window streams (RFC 9841 §6: WBITS up to 62 behind a
    /// marker a plain RFC 7932 decoder refuses; up to 30 on a 32-bit
    /// target). Off by default, as in google/brotli, since the window is
    /// what the streaming decoder holds. Distances stay below 2^31, as
    /// google/brotli's (the RFC allows a decoder that limit).
    large_window: bool = false,
    /// A serialized shared dictionary (RFC 9841 §5; `parseSharedDictionary`):
    /// its word lists and transforms stand in for (or extend) RFC 7932's
    /// static dictionary, its LZ77 dictionary is a prefix dictionary — so
    /// `dictionary` must then be empty if it has one.
    shared_dictionary: ?*const SharedDictionary = null,
    /// Called with what metadata meta-blocks carry (google/brotli's
    /// metadata callbacks); without it they are skipped.
    metadata: ?Metadata = null,

    pub const Metadata = struct {
        context: *anyopaque,
        /// A metadata meta-block of `len` bytes begins (also for 0).
        start: ?*const fn (context: *anyopaque, len: usize) void = null,
        /// Its bytes, in order, in pieces of up to 512.
        chunk: *const fn (context: *anyopaque, bytes: []const u8) void,
    };
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

        /// 10..24, or up to 62 for a large-window stream.
        wbits: u6 = 0,
        /// The stream carries the large-window marker.
        large_window: bool = false,
        /// `Options.large_window`.
        allow_large_window: bool = false,
        max_backward: usize = 0,
        /// `Options.dictionary`.
        prefix: []const u8 = &.{},
        /// `Options.metadata`.
        metadata: ?Options.Metadata = null,
        /// `Options.shared_dictionary`.
        shared: ?*const SharedDictionary = null,
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
        /// `literal_htree.entries.ptr` (and `command_entries` below): what
        /// `hotCommands` decodes with — one load less per symbol than through
        /// the `Table`, every root being `root_bits` wide.
        literal_entries: [*]const huffman.Entry = undefined,
        context_lookup: []const u8 = &.{},
        trivial_literal_context: bool = false,
        htree_command: *const Table = undefined,
        command_entries: [*]const huffman.Entry = undefined,
        dist_context_map_slice: []u8 = &.{},
        dist_htree_index: u32 = 0,
        last_distance_context: u32 = 0,

        // Where `step` stopped when the output had no room (R9: the pull
        // reader), so the next call goes on from there. Only producing
        // output stops; every header and table is read in one go.
        phase: Phase = .window,
        /// The current meta-block: ISLAST, and what it still produces.
        is_last: bool = false,
        mlen: i64 = 0,
        /// A stored meta-block's bytes not copied yet.
        stored_left: usize = 0,
        cmd_phase: CmdPhase = .header,
        cmd_v: tables.CmdLutElement = undefined,
        insert_len: u32 = 0,
        insert_left: u32 = 0,
        copy_len: u32 = 0,
        /// A distance past the window (`hotCommands` read it).
        far_distance: i32 = 0,
        /// What the command's copy (or word) adds to the output in all.
        pending_len: usize = 0,
        /// A copy still to make: `copy_left` bytes from `copy_dist` back.
        copy_left: usize = 0,
        copy_dist: usize = 0,
        /// A copy out of the prefix dictionary: `dict_left` bytes from
        /// `dict_addr` before `copy_left` from the window.
        dict_addr: usize = 0,
        dict_left: usize = 0,
        /// A static-dictionary word (transformed), `word_off` of it out —
        /// room for a custom transform's 255-byte prefix and suffix around a
        /// 31-byte word (RFC 9841), more than RFC 7932's own need.
        word: [@max(transforms.maxOutputLen(dict.max_word_length), 2 * shared.max_affix_len + shared.max_word_length)]u8 = undefined,
        word_len: usize = 0,
        word_off: usize = 0,

        const Phase = enum { window, metablock, stored, commands, metablock_end, done };
        const CmdPhase = enum { header, literals, distance, far, dict_copy, copy, word };
        /// `step` stopped: the stream ended, or output is waiting — the
        /// window has no room left, or a meta-block ended (what it produced
        /// goes out before the next one is read, which may fail).
        pub const Progress = enum { done, yield };

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
            return self.readHuffmanCodeLimited(alphabet_size, alphabet_size);
        }

        /// A code over an alphabet of `alphabet_max` symbols of which only the
        /// first `alphabet_size` may occur (a large window's distances): a
        /// simple code's symbols are `alphabet_max` wide.
        fn readHuffmanCodeLimited(self: *Self, alphabet_max: u32, alphabet_size: u32) Error!Table {
            const kind = try self.br.takeBits(2);
            if (kind == 1) {
                // Simple prefix code.
                const max_bits = huffman.symbolBits(alphabet_max - 1);
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
            return self.readTreeGroupLimited(alphabet_size, alphabet_size, count);
        }

        fn readTreeGroupLimited(self: *Self, alphabet_max: u32, alphabet_size: u32, count: u32) Error![]Table {
            const group = try self.arena.alloc(Table, count);
            var i: u32 = 0;
            while (i < count) : (i += 1) group[i] = try self.readHuffmanCodeLimited(alphabet_max, alphabet_size);
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
            self.literal_entries = self.literal_htree.entries.ptr;
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
        inline fn takeDistanceFromRingBuffer(self: *Self, code: u32) i32 {
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

        inline fn readDistance(self: *Self) Error!i32 {
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
            // A large-window stream's distance codes are read as from an
            // alphabet for 62 extra bits (the simple codes' symbol width),
            // but only those whose distances stay within
            // `max_allowed_distance` are valid (`distanceLimit`).
            const dist_alphabet_max = tables.distanceAlphabetSize(self.npostfix, self.ndirect, if (self.large_window) tables.large_max_distance_bits else tables.max_distance_bits);
            const dist_alphabet_size = if (self.large_window) tables.distanceLimit(self.npostfix, self.ndirect) else dist_alphabet_max;
            self.literal_group = try self.readTreeGroup(tables.num_literal_symbols, self.num_literal_htrees);
            self.command_group = try self.readTreeGroup(tables.num_command_symbols, self.num_block_types[1]);
            self.distance_group = try self.readTreeGroupLimited(dist_alphabet_max, dist_alphabet_size, self.num_dist_htrees);

            // Prepare cursors.
            self.prepareLiteralDecoding();
            self.dist_context_map_slice = self.dist_context_map[0..];
            self.htree_command = &self.command_group[0];
            self.command_entries = self.htree_command.entries.ptr;
            try self.calculateDistanceLut(dist_alphabet_size);

            self.out.hint(@intCast(mlen));
            self.mlen = mlen;
            self.cmd_phase = .header;
        }

        /// The meta-block's commands, while the output has room: false when it
        /// ran out mid-command (all that is needed to go on is in `self`).
        /// The checks — and the `reserve`s, so the output cap — come where
        /// they came when a command ran in one piece.
        fn runCommands(self: *Self) Error!bool {
            while (true) {
                // A command the window cut short, or one a loop below left.
                if (self.cmd_phase != .header and !try self.resumeCommand()) return false;
                const r = if (self.hotReady()) try self.hotCommands(self.out) else try self.slowCommands();
                if (r == .done) return true;
            }
        }

        /// How `hotCommands` / `slowCommands` stopped: the meta-block is
        /// done; a command is set up in `self` for `resumeCommand`; or the
        /// other loop should go on.
        const Outcome = enum { done, again, slow, fast };

        /// Sixteen input bytes at hand: what a command header needs, with
        /// its two refills, in `hotCommands`.
        fn hotReady(self: *const Self) bool {
            return self.br.data.len - self.br.byte_pos >= hot_margin;
        }

        /// Commands while each fits the output whole, copies from the window
        /// and the input has `hot_margin` bytes at hand, with the bit reader
        /// in locals (`HotBits`): behind `self.br` its state was stored and
        /// loaded around every output byte, as an output byte may land
        /// anywhere for the compiler (perf annotate, 2026-10-15). A read
        /// never fetches input here: a header and a distance start only with
        /// `hot_margin` bytes at hand, a literal only with eight; short of
        /// them the command is handed to `resumeCommand` (literals,
        /// distance) or the next to `slowCommands` (header). Lengths are
        /// locals too and nothing is called out of line but block switches
        /// (measured: each worth ~10 % on `d_text`).
        /// `ensureRoom` from `hotCommands`: a streaming sink bounds the output
        /// by the input consumed (`effectiveCap`), which is `h`'s position.
        inline fn hotRoom(self: *Self, out: *Sink, h: *const HotBits, n: usize) Error!void {
            if (Sink == RingSink) self.br.byte_pos = h.pos;
            try out.reserve(n, self.br);
        }

        /// `noalias`: the output is written through `out`'s buffer, which is
        /// neither `self` nor `out`, so LLVM keeps their fields in registers
        /// across those stores instead of loading them again after each
        /// (2–3 % of decoding, 2026-10-16).
        fn hotCommands(noalias self: *Self, noalias out: *Sink) Error!Outcome {
            var mlen = self.mlen;
            defer self.mlen = mlen;
            var h = HotBits.load(self.br);
            defer h.store(self.br);
            while (mlen > 0) {
                // Command block switch.
                if (self.block_length[1] == 0) {
                    h.store(self.br);
                    try self.decodeBlockTypeAndLength(1);
                    h = HotBits.load(self.br);
                    self.htree_command = &self.command_group[self.block_type_rb[1][1]];
                    self.command_entries = self.htree_command.entries.ptr;
                }
                if (!h.hasMargin()) return .slow;
                h.top();
                const cmd = h.symbol(self.command_entries);
                self.block_length[1] -= 1;
                if (cmd >= tables.num_command_symbols) return error.InvalidHuffman;
                const v = tables.cmd_lut[cmd];
                const insert_len: u32 = v.insert_len_offset + h.bits(v.insert_len_extra_bits);
                const copy_len: u32 = v.copy_len_offset + h.bits(v.copy_len_extra_bits);
                self.dist_htree_index = self.dist_context_map_slice[v.context];

                // Insert literals.
                try self.hotRoom(out, &h, insert_len);
                var done: u32 = 0;
                if (insert_len <= out.room()) {
                    while (done < insert_len) : (done += 1) {
                        if (self.block_length[0] == 0) {
                            h.store(self.br);
                            try self.decodeBlockTypeAndLength(0);
                            h = HotBits.load(self.br);
                            self.prepareLiteralDecoding();
                        }
                        if ((comptime @hasDecl(Sink, "tailPtr")) and insert_len - done >= fast_literals_min) {
                            // As google/brotli's literal loop (`decode.c`,
                            // `BrotliCopyPreloadedSymbolsToU8`): the literals that
                            // need no check — within the insert and the block, and
                            // what the input holds at 15 bits each with a refill's
                            // margin — in a loop of their own, writing through a
                            // local pointer with the tables and the two context
                            // bytes in locals. Through `self.out` every byte stored
                            // made the compiler load `self`'s fields again.
                            // At most 15 bits a literal: half a literal a byte is
                            // below that, and a shift.
                            const by_input = ((h.len - h.pos) -| hot_margin) / 2;
                            const n: u32 = @intCast(@min(insert_len - done, self.block_length[0], by_input));
                            if (n != 0) {
                                const dst = out.tailPtr();
                                if (self.trivial_literal_context) {
                                    const t = self.literal_entries;
                                    for (dst[0..n]) |*o| o.* = @intCast(h.symbol(t));
                                } else {
                                    const len = out.pos();
                                    var p1: u8 = if (len >= 1) out.back(1) else 0;
                                    var p2: u8 = if (len >= 2) out.back(2) else 0;
                                    const lut = self.context_lookup[0..512];
                                    const map = self.context_map_slice[0..64];
                                    const group = self.literal_group;
                                    for (dst[0..n]) |*o| {
                                        const b: u8 = @intCast(h.symbol(group[map[lut[p1] | lut[256 + @as(usize, p2)]]].entries.ptr));
                                        o.* = b;
                                        p2 = p1;
                                        p1 = b;
                                    }
                                }
                                out.advance(n);
                                self.block_length[0] -= n;
                                done += n - 1; // the loop adds the last one
                                continue;
                            }
                        }
                        if (h.cnt < 15) {
                            if (!h.canRefill()) break;
                            h.refill();
                        }
                        var lit: u16 = undefined;
                        if (self.trivial_literal_context) {
                            lit = h.symbol(self.literal_entries);
                        } else {
                            const len = out.pos();
                            const p1: u8 = if (len >= 1) out.back(1) else 0;
                            const p2: u8 = if (len >= 2) out.back(2) else 0;
                            const context = self.context_lookup[p1] | self.context_lookup[256 + @as(usize, p2)];
                            lit = h.symbol(self.literal_group[self.context_map_slice[context]].entries.ptr);
                        }
                        try out.put(@intCast(lit));
                        self.block_length[0] -= 1;
                    }
                }
                if (done < insert_len) {
                    // The window is short of the insert, or the input of a
                    // literal: the rest from `resumeCommand`.
                    @branchHint(.unlikely);
                    self.cmd_v = v;
                    self.insert_len = insert_len;
                    self.copy_len = copy_len;
                    self.insert_left = insert_len - done;
                    self.cmd_phase = .literals;
                    return .again;
                }
                mlen -= insert_len;
                // RFC 7932 9.2: the commands produce exactly MLEN bytes.
                if (mlen < 0) return error.InvalidLength;
                if (mlen == 0) break;

                var distance: i32 = undefined;
                if (v.distance_code >= 0) {
                    // Implicit (== 0): reuse last distance.
                    self.last_distance_context = 1;
                    self.dist_rb_idx -%= 1;
                    distance = self.dist_rb[self.dist_rb_idx & 3];
                } else {
                    if (self.block_length[2] == 0) {
                        h.store(self.br);
                        try self.decodeBlockTypeAndLength(2);
                        h = HotBits.load(self.br);
                        self.dist_context_map_slice = self.dist_context_map[self.block_type_rb[2][1] * 4 ..][0..4];
                        self.dist_htree_index = self.dist_context_map_slice[v.context];
                    }
                    if (!h.hasMargin()) {
                        @branchHint(.unlikely);
                        self.cmd_v = v;
                        self.copy_len = copy_len;
                        self.cmd_phase = .distance;
                        return .again;
                    }
                    h.top();
                    const code = h.symbol(self.distance_group[self.dist_htree_index].entries.ptr);
                    self.block_length[2] -= 1;
                    self.last_distance_context = 0;
                    if ((code & ~@as(u16, 0xf)) == 0) {
                        distance = self.takeDistanceFromRingBuffer(code);
                    } else {
                        if (code >= self.dist_offset.len) return error.InvalidDistance;
                        const nbits = self.dist_extra_bits[code];
                        const extra = h.bits(nbits);
                        const dv: u64 = @as(u64, self.dist_offset[code]) + (@as(u64, extra) << @intCast(self.npostfix));
                        distance = if (dv > tables.max_allowed_distance) 0x7FFFFFFF else @intCast(dv);
                    }
                }
                const pos = out.pos();
                const max_distance: i64 = @min(@as(i64, @intCast(pos)), @as(i64, @intCast(self.max_backward)));
                if (@as(i64, distance) > max_distance) {
                    // The prefix or the static dictionary: set up and made
                    // as a cut-short command is.
                    @branchHint(.unlikely);
                    self.copy_len = copy_len;
                    self.far_distance = distance;
                    self.cmd_phase = .far;
                    return .again;
                }
                // Normal LZ77 backward copy.
                const copy: usize = copy_len;
                if (distance <= 0) return error.InvalidDistance;
                const d: usize = @intCast(distance);
                if (d > pos) return error.InvalidDistance;
                self.dist_rb[self.dist_rb_idx & 3] = distance;
                self.dist_rb_idx +%= 1;
                try self.hotRoom(out, &h, copy);
                if (copy > out.room()) {
                    @branchHint(.unlikely);
                    self.copy_left = copy;
                    self.copy_dist = d;
                    self.pending_len = copy;
                    self.cmd_phase = .copy;
                    return .again;
                }
                try out.copyBack(d, copy);
                mlen -= @intCast(copy);
                if (mlen < 0) return error.InvalidLength;
            }
            return .done;
        }

        fn slowCommands(self: *Self) Error!Outcome {
            var mlen = self.mlen;
            defer self.mlen = mlen;
            while (mlen > 0) {
                // Eight bytes at hand again (a new chunk): back to the hot loop.
                if (self.hotReady()) return .fast;
                // Command block switch.
                if (self.block_length[1] == 0) {
                    try self.decodeBlockTypeAndLength(1);
                    self.htree_command = &self.command_group[self.block_type_rb[1][1]];
                    self.command_entries = self.htree_command.entries.ptr;
                }
                const cmd = try self.br.readSymbol(self.htree_command);
                self.block_length[1] -= 1;
                if (cmd >= tables.num_command_symbols) return error.InvalidHuffman;
                const v = tables.cmd_lut[cmd];
                const insert_len: u32 = v.insert_len_offset + try self.br.takeBits(v.insert_len_extra_bits);
                const copy_len: u32 = v.copy_len_offset + try self.br.takeBits(v.copy_len_extra_bits);
                self.dist_htree_index = self.dist_context_map_slice[v.context];

                // Insert literals.
                try self.ensureRoom(insert_len);
                if (insert_len > self.out.room()) {
                    @branchHint(.unlikely);
                    self.cmd_v = v;
                    self.insert_len = insert_len;
                    self.copy_len = copy_len;
                    self.insert_left = insert_len;
                    self.cmd_phase = .literals;
                    return .again;
                }
                try self.literals(insert_len);
                mlen -= insert_len;
                // RFC 7932 9.2: the commands produce exactly MLEN bytes.
                if (mlen < 0) return error.InvalidLength;
                if (mlen == 0) break;

                const distance = try self.commandDistance(v);
                const pos = self.out.pos();
                const max_distance: i64 = @min(@as(i64, @intCast(pos)), @as(i64, @intCast(self.max_backward)));
                if (@as(i64, distance) > max_distance) {
                    // The prefix or the static dictionary: set up and made
                    // as a cut-short command is.
                    @branchHint(.unlikely);
                    self.copy_len = copy_len;
                    self.far_distance = distance;
                    self.cmd_phase = .far;
                    return .again;
                }
                // Normal LZ77 backward copy.
                const copy: usize = copy_len;
                if (distance <= 0) return error.InvalidDistance;
                const d: usize = @intCast(distance);
                if (d > pos) return error.InvalidDistance;
                self.dist_rb[self.dist_rb_idx & 3] = distance;
                self.dist_rb_idx +%= 1;
                try self.ensureRoom(copy);
                if (copy > self.out.room()) {
                    @branchHint(.unlikely);
                    self.copy_left = copy;
                    self.copy_dist = d;
                    self.pending_len = copy;
                    self.cmd_phase = .copy;
                    return .again;
                }
                try self.out.copyBack(d, copy);
                mlen -= @intCast(copy);
                if (mlen < 0) return error.InvalidLength;
            }
            return .done;
        }

        /// Go on with a command from `cmd_phase` (state in `self`, `mlen`
        /// included): true when it is done, false when the window filled.
        fn resumeCommand(self: *Self) Error!bool {
            while (true) switch (self.cmd_phase) {
                .header => return true,
                .literals => {
                    const n: u32 = @intCast(@min(self.insert_left, self.out.room()));
                    try self.literalsCold(n);
                    self.insert_left -= n;
                    if (self.insert_left != 0) return false;
                    self.mlen -= self.insert_len;
                    if (self.mlen < 0) return error.InvalidLength;
                    if (self.mlen == 0) {
                        self.cmd_phase = .header;
                        return true;
                    }
                    self.cmd_phase = .distance;
                },
                .distance => try self.startCopy(try self.commandDistance(self.cmd_v)),
                .far => try self.startCopy(self.far_distance),
                .dict_copy => {
                    const n = @min(self.dict_left, self.out.room());
                    try self.out.putSlice(self.prefix[self.dict_addr..][0..n]);
                    self.dict_addr += n;
                    self.dict_left -= n;
                    if (self.dict_left != 0) return false;
                    self.cmd_phase = .copy;
                },
                .copy => {
                    const n = @min(self.copy_left, self.out.room());
                    if (n != 0) try self.out.copyBack(self.copy_dist, n);
                    self.copy_left -= n;
                    if (self.copy_left != 0) return false;
                    try self.endCopy();
                },
                .word => {
                    const n = @min(self.word_len - self.word_off, self.out.room());
                    try self.out.putSlice(self.word[self.word_off..][0..n]);
                    self.word_off += n;
                    if (self.word_off != self.word_len) return false;
                    try self.endCopy();
                },
            };
        }

        /// `literals`, out of the hot loop.
        noinline fn literalsCold(self: *Self, n: u32) Error!void {
            try self.literals(n);
        }

        /// `n` of the command's literals (room reserved).
        inline fn literals(self: *Self, n: u32) Error!void {
            var j: u32 = 0;
            while (j < n) : (j += 1) {
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
                // Room for the whole insert was reserved above.
                try self.out.put(@intCast(lit));
                self.block_length[0] -= 1;
            }
        }

        /// The command's copy has all gone out.
        fn endCopy(self: *Self) Error!void {
            self.mlen -= @intCast(self.pending_len);
            if (self.mlen < 0) return error.InvalidLength;
            self.cmd_phase = .header;
        }

        /// The command's distance: implicit (the last), or read — after a
        /// distance block switch if one is due.
        inline fn commandDistance(self: *Self, v: tables.CmdLutElement) Error!i32 {
            if (v.distance_code >= 0) {
                // Implicit (== 0): reuse last distance.
                self.last_distance_context = 1;
                self.dist_rb_idx -%= 1;
                return self.dist_rb[self.dist_rb_idx & 3];
            }
            if (self.block_length[2] == 0) {
                try self.decodeBlockTypeAndLength(2);
                self.dist_context_map_slice = self.dist_context_map[self.block_type_rb[2][1] * 4 ..][0..4];
                // A distance block switch re-selects the htree for the
                // command's current distance context (RFC 7932 / reference).
                self.dist_htree_index = self.dist_context_map_slice[v.context];
            }
            return self.readDistance();
        }

        /// Set the command's copy at `distance` up (`dict_copy`, `copy` or
        /// `word`), for `resumeCommand` to make.
        fn startCopy(self: *Self, distance: i32) Error!void {
            const pos = self.out.pos();
            const max_distance: i64 = @min(@as(i64, @intCast(pos)), @as(i64, @intCast(self.max_backward)));
            const copy: usize = self.copy_len;

            if (@as(i64, distance) > max_distance and @as(i64, distance) - max_distance <= self.prefix.len) {
                // Into the prefix dictionary, which sits just before the
                // window; a copy running past its end goes on at the
                // window's start (RFC 9841 §3.2). A regular copy
                // otherwise: its distance enters the ring.
                const dlen = self.prefix.len;
                const addr: usize = dlen + @as(usize, @intCast(max_distance)) - @as(usize, @intCast(distance));
                const from_dict = @min(copy, dlen - addr);
                self.dist_rb[self.dist_rb_idx & 3] = distance;
                self.dist_rb_idx +%= 1;
                try self.ensureRoom(copy);
                self.dict_addr = addr;
                self.dict_left = from_dict;
                self.copy_left = copy - from_dict;
                self.copy_dist = from_dict + @as(usize, @intCast(max_distance));
                self.pending_len = copy;
                self.cmd_phase = .dict_copy;
            } else if (@as(i64, distance) > max_distance) {
                // Static-dictionary reference (its word ids start past
                // the prefix dictionary).
                if (distance > tables.max_allowed_distance) return error.InvalidDistance;
                if (self.shared) |sd| if (sd.custom()) {
                    const address: u64 = @intCast(@as(i64, distance) - max_distance - 1 - @as(i64, @intCast(self.prefix.len)));
                    self.dist_rb_idx +%= self.last_distance_context;
                    const wlen = try self.customWord(sd, address, copy);
                    try self.ensureRoom(wlen);
                    self.word_len = wlen;
                    self.word_off = 0;
                    self.pending_len = wlen;
                    self.cmd_phase = .word;
                    return;
                };
                if (copy < dict.min_word_length or copy > dict.max_word_length) return error.InvalidDictionary;
                const shift = dict.size_bits_by_length[copy];
                if (shift == 0) return error.InvalidDictionary;
                const address: i64 = @as(i64, distance) - max_distance - 1 - @as(i64, @intCast(self.prefix.len));
                const word_mask: i64 = (@as(i64, 1) << @intCast(shift)) - 1;
                const word_idx: usize = @intCast(address & word_mask);
                const transform_idx: i64 = address >> @intCast(shift);
                self.dist_rb_idx +%= self.last_distance_context;
                if (transform_idx < 0 or transform_idx >= transforms.num_transforms) return error.InvalidDictionary;
                const woff = dict.offsets_by_length[copy] + word_idx * copy;
                if (woff + copy > dict.data.len) return error.InvalidDictionary;
                const word = dict.data[woff..][0..copy];
                // `copy` is bounded to `dict.max_word_length` above, so
                // `self.word`, sized from the same tables, provably holds any
                // transform output even under ReleaseFast (no magic constant).
                var wlen: usize = undefined;
                if (transform_idx == 0) {
                    @memcpy(self.word[0..copy], word);
                    wlen = copy;
                } else {
                    wlen = transforms.transformWord(&self.word, word, copy, @intCast(transform_idx));
                    if (wlen == 0 and distance <= 120) return error.InvalidDictionary;
                }
                try self.ensureRoom(wlen);
                self.word_len = wlen;
                self.word_off = 0;
                self.pending_len = wlen;
                self.cmd_phase = .word;
            } else {
                // Normal LZ77 backward copy.
                if (distance <= 0) return error.InvalidDistance;
                const d: usize = @intCast(distance);
                if (d > pos) return error.InvalidDistance;
                self.dist_rb[self.dist_rb_idx & 3] = distance;
                self.dist_rb_idx +%= 1;
                try self.ensureRoom(copy);
                self.copy_left = copy;
                self.copy_dist = d;
                self.pending_len = copy;
                self.cmd_phase = .copy;
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

        /// Decode until the stream ends or the output has no room
        /// (`Sink.room`); called again, it goes on where it stopped. One-shot
        /// sinks always have room: one call decodes everything.
        fn step(self: *Self) Error!Progress {
            while (true) switch (self.phase) {
                .window => {
                    const wb = try decodeWindowBits(self.br, self.allow_large_window);
                    self.wbits = wb.wbits;
                    self.large_window = wb.large;
                    self.max_backward = (@as(usize, 1) << @intCast(self.wbits)) - 16;
                    try self.out.setWindow(self.wbits);
                    self.phase = .metablock;
                },
                .metablock => {
                    // Nothing from the previous meta-block is read again: every
                    // table and cursor is rebuilt before the next command.
                    _ = self.arena_state.reset(.retain_capacity);
                    self.resetMetablock();
                    const h = try self.decodeMetaBlockLength();
                    self.is_last = h.is_last;
                    if (h.is_metadata or h.is_uncompressed) try self.br.jumpToByteBoundary();

                    if (h.is_metadata) {
                        try self.metadataBlock(@intCast(h.mlen));
                        if (h.is_last) try self.endStream();
                        continue;
                    }
                    if (h.mlen == 0) {
                        if (h.is_last) try self.endStream();
                        continue;
                    }
                    if (h.mlen > block_size_cap) return error.InvalidLength;

                    if (h.is_uncompressed) {
                        const n: usize = @intCast(h.mlen);
                        try self.out.reserveStored(n, self.br);
                        self.stored_left = n;
                        self.phase = .stored;
                    } else {
                        try self.decodeCompressedMetablock(h.mlen);
                        self.phase = .commands;
                    }
                },
                .stored => {
                    const n = @min(self.stored_left, self.out.room());
                    try self.out.readAligned(self.br, n);
                    self.stored_left -= n;
                    if (self.stored_left != 0) return .yield;
                    self.phase = .metablock_end;
                },
                .commands => {
                    if (!try self.runCommands()) return .yield;
                    self.phase = .metablock_end;
                },
                .metablock_end => {
                    try self.out.endMetablock();
                    if (self.is_last) {
                        try self.endStream();
                    } else {
                        self.phase = .metablock;
                        return .yield;
                    }
                },
                .done => return .done,
            };
        }

        /// A static-dictionary word under a serialized shared dictionary
        /// (RFC 9841 §3.1) into `self.word`, its length returned. `address`
        /// counts through the dictionaries in turn — the current literal
        /// context's first when the dictionary is context dependent, then the
        /// others in their order: past one dictionary's words × transforms
        /// for this length, it goes on in the next.
        fn customWord(self: *Self, sd: *const SharedDictionary, address_in: u64, len: usize) Error!usize {
            if (len < shared.min_word_length or len > shared.max_word_length) return error.InvalidDictionary;
            const nd = sd.dictionaries.len;
            var first: usize = 0;
            if (sd.context_map) |cm| {
                const pos = self.out.pos();
                const p1: u8 = if (pos >= 1) self.out.back(1) else 0;
                const p2: u8 = if (pos >= 2) self.out.back(2) else 0;
                first = cm[self.context_lookup[p1] | self.context_lookup[256 + @as(usize, p2)]];
            }
            var address = address_in;
            for (0..nd) |k| {
                const di = if (k == 0) first else if (k <= first) k - 1 else k;
                const pair = sd.dictionaries[di];
                const words = pair.words orelse &shared.WordList.builtin;
                const nw = words.count(len);
                const nt: usize = if (pair.transforms) |t| t.len() else transforms.num_transforms;
                const span = @as(u64, nw) * nt;
                if (address >= span) {
                    address -= span;
                    continue;
                }
                const word = words.word(len, @intCast(address & (nw - 1)));
                const ti: usize = @intCast(address >> @intCast(words.size_bits[len]));
                if (pair.transforms) |t| {
                    const tri = t.triplets[3 * ti ..][0..3];
                    return transforms.applyOp(&self.word, t.affix(tri[0]), tri[1], t.param(ti), t.affix(tri[2]), word);
                }
                return transforms.transformWord(&self.word, word, len, ti);
            }
            return error.InvalidDictionary;
        }

        /// After the last meta-block: the fill bits to the byte boundary must
        /// be zero (RFC 7932 §9.2, as google/brotli checks), and what the bit
        /// reader read past them goes back to the input.
        fn endStream(self: *Self) Error!void {
            try self.br.jumpToByteBoundary();
            self.br.unreadAhead();
            self.phase = .done;
        }

        /// A metadata meta-block's `n` bytes: to `Options.metadata`, or
        /// skipped.
        fn metadataBlock(self: *Self, n: usize) Error!void {
            const m = self.metadata orelse return self.br.skipAlignedBytes(n);
            if (m.start) |f| f(m.context, n);
            var buf: [512]u8 = undefined;
            var left = n;
            while (left != 0) {
                const k = @min(left, buf.len);
                try self.br.readAlignedBytes(buf[0..k]);
                m.chunk(m.context, buf[0..k]);
                left -= k;
            }
        }

        /// The whole stream (a one-shot sink: it yields only between
        /// meta-blocks).
        fn run(self: *Self) Error!void {
            while (try self.step() != .done) {}
        }
    };
}

/// The prefix dictionary `options` give: the raw one, or the shared
/// dictionary's LZ77 one — not both.
fn prefixOf(options: Options) BrotliError![]const u8 {
    const lz: []const u8 = if (options.shared_dictionary) |sd| sd.prefix else &.{};
    if (lz.len != 0 and options.dictionary.len != 0) return error.InvalidDictionary;
    return if (lz.len != 0) lz else options.dictionary;
}

const WindowBits = struct { wbits: u6, large: bool = false };

/// RFC 7932 §9.1, and RFC 9841 §6's large window behind `1 000 100 0`
/// (when `allow_large`).
fn decodeWindowBits(br: *BitReader, allow_large: bool) BrotliError!WindowBits {
    if ((try br.takeBits(1)) == 0) return .{ .wbits = 16 };
    const n = try br.takeBits(3);
    if (n != 0) return .{ .wbits = @intCast(17 + n) };
    const n2 = try br.takeBits(3);
    if (n2 == 1) {
        if (!allow_large) return error.InvalidWindowBits;
        if ((try br.takeBits(1)) != 0) return error.InvalidWindowBits;
        const w = try br.takeBits(6);
        if (w < 10 or w > tables.large_max_window_bits) return error.InvalidWindowBits;
        return .{ .wbits = @intCast(w), .large = true };
    }
    if (n2 != 0) return .{ .wbits = @intCast(8 + n2) };
    return .{ .wbits = 17 };
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

/// Bytes `ListSink` keeps allocated past every reservation.
/// Input bytes `hotCommands` needs at hand to start a command header or a
/// distance: two refills of up to eight bytes each.
const hot_margin = 16;

/// Literals left in an insert from which `hotCommands` takes them in a loop
/// without checks: on text most inserts are a literal or two, where
/// setting that loop up cost 3 % (2026-10-15).
const fast_literals_min = 8;

/// The bit reader's state in locals for `hotCommands` (same invariants as
/// `BitReader`: bits above `cnt` are zero). It never fetches a chunk: the
/// caller checks the margin (`hasMargin`, `canRefill`) before reads that may
/// refill, so a symbol read never runs short — no `TruncatedInput` checks.
const HotBits = struct {
    acc: u64,
    cnt: u32,
    pos: usize,
    data: [*]const u8,
    len: usize,

    inline fn load(br: *const BitReader) HotBits {
        return .{ .acc = br.acc, .cnt = br.cnt, .pos = br.byte_pos, .data = br.data.ptr, .len = br.data.len };
    }

    inline fn store(h: HotBits, br: *BitReader) void {
        // `refill` leaves real stream bits above `cnt`; `BitReader` keeps
        // them zero.
        br.acc = if (h.cnt >= 64) h.acc else h.acc & ((@as(u64, 1) << @intCast(h.cnt)) - 1);
        br.cnt = h.cnt;
        br.byte_pos = h.pos;
    }

    /// Two refills' worth of input at hand.
    inline fn hasMargin(h: HotBits) bool {
        return h.len - h.pos >= hot_margin;
    }

    /// One refill's worth.
    inline fn canRefill(h: HotBits) bool {
        return h.len - h.pos >= 8;
    }

    /// To 56..64 bits from any count, without a branch: `refill`'s
    /// arithmetic, which from 57..63 bits adds no byte and loads the same
    /// bits above again, and adds nothing at 64 (only right after `load`).
    /// Precondition: `canRefill`. (`if (cnt <= 56) refill()` was a third of
    /// the decoder's branch misses on text, 2026-10-16: whether a command
    /// header needs a refill is data.)
    inline fn top(h: *HotBits) void {
        const full: u64 = @intFromBool(h.cnt >= 64);
        const x = std.mem.readInt(u64, h.data[h.pos..][0..8], .little);
        h.acc |= (x << @as(u6, @truncate(h.cnt))) & (full -% 1);
        h.pos += (63 -| h.cnt) >> 3;
        h.cnt = @min(h.cnt | 56, 64);
    }

    /// Branch-free: the whole next eight bytes are or-ed in above `cnt`;
    /// only the whole bytes counted move `pos`, so the bits of the partial
    /// byte above are loaded again, the same, by the next refill.
    inline fn refill(h: *HotBits) void {
        h.acc |= std.mem.readInt(u64, h.data[h.pos..][0..8], .little) << @intCast(h.cnt);
        h.pos += (63 - h.cnt) >> 3;
        h.cnt |= 56;
    }

    /// A symbol (codes are at most 15 bits). Precondition: 15 bits held,
    /// or `canRefill`.
    inline fn symbol(h: *HotBits, entries: [*]const huffman.Entry) u16 {
        if (h.cnt < 15) h.refill();
        // Every root is `root_bits` wide: a constant mask.
        const idx: usize = @truncate(h.acc & ((1 << huffman.root_bits) - 1));
        var e = entries[idx];
        if (e.len & huffman.link_flag != 0) {
            const sub_bits: u6 = @intCast(e.len & ~huffman.link_flag);
            const sub: usize = @truncate((h.acc >> huffman.root_bits) & ((@as(u64, 1) << sub_bits) - 1));
            e = entries[@as(usize, e.sym) + sub];
        }
        h.acc >>= @intCast(e.len);
        h.cnt -= e.len;
        return e.sym;
    }

    /// `n` (0..32) bits. Precondition: `n` bits held, or `canRefill`.
    inline fn bits(h: *HotBits, n: u32) u32 {
        if (h.cnt < n) h.refill();
        const v: u32 = @truncate(h.acc & ((@as(u64, 1) << @intCast(n)) - 1));
        h.acc >>= @intCast(n);
        h.cnt -= n;
        return v;
    }
};

const copy_slack = 32;

/// `buf[dst..][0..16] = buf[src..][0..16]` through a register (the ranges may
/// overlap when `dst - src < 16`; the bytes read are those before the store).
inline fn copy16(buf: []u8, dst: usize, src: usize) void {
    const v = std.mem.readInt(u128, buf[src..][0..16], .little);
    std.mem.writeInt(u128, buf[dst..][0..16], v, .little);
}

inline fn copy32(buf: []u8, dst: usize, src: usize) void {
    const v: @Vector(32, u8) = buf[src..][0..32].*;
    buf[dst..][0..32].* = v;
}

/// One-shot output: the whole output is the window.
const ListSink = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayListUnmanaged(u8) = .empty,
    cap: usize,

    const WriteError = error{};

    inline fn pos(s: *const ListSink) usize {
        return s.list.items.len;
    }
    /// Unbounded: `reserve` grows the list (or refuses past the cap).
    fn room(_: *const ListSink) usize {
        return std.math.maxInt(usize);
    }
    inline fn back(s: *const ListSink, d: usize) u8 {
        return s.list.items[s.list.items.len - d];
    }
    /// Room for `n` more bytes plus `copy_slack` past them, which
    /// `copyBack`'s 16-byte stores may overrun.
    inline fn reserve(s: *ListSink, n: usize, _: *const BitReader) BrotliError!void {
        if (s.list.items.len + n > s.cap) return error.OutputTooLarge;
        if (s.list.capacity - s.list.items.len >= n + copy_slack) return; // usually: `hint` grew it
        try s.list.ensureUnusedCapacity(s.gpa, n + copy_slack);
    }
    fn reserveStored(s: *ListSink, n: usize, br: *const BitReader) BrotliError!void {
        return s.reserve(n, br);
    }
    /// As `SliceSink.tailPtr`: within the capacity `reserve` made.
    inline fn tailPtr(s: *ListSink) [*]u8 {
        return s.list.items.ptr + s.list.items.len;
    }
    inline fn advance(s: *ListSink, n: usize) void {
        s.list.items.len += n;
    }
    inline fn put(s: *ListSink, b: u8) BrotliError!void {
        s.list.appendAssumeCapacity(b);
    }
    fn putSlice(s: *ListSink, bytes: []const u8) BrotliError!void {
        s.list.appendSliceAssumeCapacity(bytes);
    }
    /// Append `n` bytes copied from `d` back (after `reserve(n)`). An
    /// overlapping copy (d < n) repeats the last `d` bytes, as LZ77 requires:
    /// it goes in chunks of `d`, each a non-overlapping copy of bytes already
    /// written; a short period goes byte by byte.
    ///
    /// Most copies are short (95 % under 16 bytes in google/brotli's q9 text):
    /// they go as 16- or 32-byte loads and stores, which may write up to 31
    /// bytes of garbage past the copy into the `copy_slack` room `reserve` keeps --
    /// overwritten by whatever comes next, never part of the output.
    inline fn copyBack(s: *ListSink, d: usize, n: usize) BrotliError!void {
        copyBackSlack(s.list.allocatedSlice(), s.list.items.len, d, n);
        s.list.items.len += n;
    }
    /// The next `n` bytes are coming (a meta-block's length): grow once, up
    /// to the cap, instead of doubling through it. A failure here is left to
    /// `reserve`, which reports it at the byte that needs the room.
    fn hint(s: *ListSink, n: usize) void {
        const want = @min(n, s.cap -| s.list.items.len);
        s.list.ensureUnusedCapacity(s.gpa, want) catch {};
    }
    fn readAligned(s: *ListSink, br: *BitReader, n: usize) BrotliError!void {
        const start = s.list.items.len;
        s.list.items.len += n;
        try br.readAlignedBytes(s.list.items[start..][0..n]);
    }
    fn setWindow(_: *ListSink, _: u6) BrotliError!void {}
    fn endMetablock(_: *ListSink) BrotliError!void {}
};

/// `buf[start..][0..n] = ` the bytes `d` back, LZ77 style, with up to
/// `copy_slack` bytes of garbage written past the copy (see
/// `ListSink.copyBack`). Precondition: `start + n + copy_slack <= buf.len`.
inline fn copyBackSlack(buf: []u8, start: usize, d: usize, n: usize) void {
    if (n <= 16 and d >= 16) {
        // The common case: one 16-byte move. A wider load than the copy
        // needs reaches bytes stored just before, which the CPU cannot
        // forward from a narrower store (measured: 7.7 % on text).
        copy16(buf, start, start - d);
    } else if (d >= 32) {
        // Each chunk's source ends at or before its destination starts;
        // a source byte inside an earlier chunk was written already.
        var k: usize = 0;
        while (k < n) : (k += 32) copy32(buf, start + k, start + k - d);
    } else if (d >= 16) {
        var k: usize = 0;
        while (k < n) : (k += 16) copy16(buf, start + k, start + k - d);
    } else if (d >= n) {
        copy16(buf, start, start - d); // n ≤ d < 16: one store
    } else {
        for (start..start + n) |i| buf[i] = buf[i - d];
    }
}

/// One-shot output into the caller's buffer: the buffer is the window.
const SliceSink = struct {
    buf: []u8,
    len: usize = 0,
    /// `min(buf.len, effectiveCap)`.
    cap: usize,

    const WriteError = error{};

    inline fn pos(s: *const SliceSink) usize {
        return s.len;
    }
    /// Unbounded: `reserve` refuses what does not fit the buffer.
    fn room(_: *const SliceSink) usize {
        return std.math.maxInt(usize);
    }
    inline fn back(s: *const SliceSink, d: usize) u8 {
        return s.buf[s.len - d];
    }
    inline fn reserve(s: *SliceSink, n: usize, _: *const BitReader) BrotliError!void {
        if (s.len + n > s.cap) return error.OutputTooLarge;
    }
    fn reserveStored(s: *SliceSink, n: usize, br: *const BitReader) BrotliError!void {
        return s.reserve(n, br);
    }
    /// Where the next output byte goes: a run of literals `reserve` made
    /// room for is written there, then `advance`d over.
    inline fn tailPtr(s: *SliceSink) [*]u8 {
        return s.buf.ptr + s.len;
    }
    inline fn advance(s: *SliceSink, n: usize) void {
        s.len += n;
    }
    inline fn put(s: *SliceSink, b: u8) BrotliError!void {
        s.buf[s.len] = b;
        s.len += 1;
    }
    fn putSlice(s: *SliceSink, bytes: []const u8) BrotliError!void {
        @memcpy(s.buf[s.len..][0..bytes.len], bytes);
        s.len += bytes.len;
    }
    /// The fast moves of `copyBackSlack` while the caller's buffer has the
    /// slack past the copy; near its end, exact copies.
    inline fn copyBack(s: *SliceSink, d: usize, n: usize) BrotliError!void {
        const start = s.len;
        if (start + n + copy_slack <= s.buf.len) {
            copyBackSlack(s.buf, start, d, n);
        } else if (d >= n) {
            @memcpy(s.buf[start..][0..n], s.buf[start - d ..][0..n]);
        } else {
            for (start..start + n) |i| s.buf[i] = s.buf[i - d];
        }
        s.len += n;
    }
    fn hint(_: *SliceSink, _: usize) void {}
    fn readAligned(s: *SliceSink, br: *BitReader, n: usize) BrotliError!void {
        try br.readAlignedBytes(s.buf[s.len..][0..n]);
        s.len += n;
    }
    fn setWindow(_: *SliceSink, _: u6) BrotliError!void {}
    fn endMetablock(_: *SliceSink) BrotliError!void {}
};

/// Decompress a complete Brotli stream into `out`; returns the decoded prefix
/// of it. Output that does not fit `out` (or the `options` cap) is
/// `OutputTooLarge`, and `out` then holds a partial result. `gpa` holds the
/// decoding tables only. For a caller that knows the size, or reuses one
/// buffer: no allocation of the output and no growing it.
pub fn decompressInto(gpa: std.mem.Allocator, out: []u8, input: []const u8, options: Options) BrotliError![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var br = BitReader.init(input);
    var sink: SliceSink = .{ .buf = out, .cap = @min(out.len, effectiveCap(options, input.len)) };
    var dec = DecoderOf(SliceSink){
        .arena_state = &arena_state,
        .arena = arena_state.allocator(),
        .br = &br,
        .out = &sink,
        .prefix = try prefixOf(options),
        .allow_large_window = options.large_window,
        .metadata = options.metadata,
        .shared = options.shared_dictionary,
    };
    try dec.run();
    return out[0..sink.len];
}

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
        .prefix = try prefixOf(options),
        .allow_large_window = options.large_window,
        .metadata = options.metadata,
        .shared = options.shared_dictionary,
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
    options: Options,
    buf: []u8 = &.{},
    mask: usize = 0,
    /// What the ring may grow to: the window, or less under a small cap.
    limit: usize = 0,
    total: usize = 0,
    flushed: usize = 0,

    const initial_len: usize = 1 << 16;

    const WriteError = error{};
    const Error = BrotliError;

    fn deinit(s: *RingSink) void {
        s.gpa.free(s.buf);
    }
    /// Bytes that may be produced before the oldest not handed out
    /// (`drain`) would be overwritten.
    fn room(s: *const RingSink) usize {
        return s.limit - (s.total - s.flushed);
    }
    fn unflushed(s: *const RingSink) usize {
        return s.total - s.flushed;
    }
    /// Hand out the oldest bytes not handed out yet (one contiguous piece
    /// of the ring, at most `limit`) to `w`.
    fn drain(s: *RingSink, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Writer.Error!usize {
        const at = s.flushed & s.mask;
        const k = @min(s.total - s.flushed, s.buf.len - at);
        const n = try w.write(limit.sliceConst(s.buf[at..][0..k]));
        s.flushed += n;
        return n;
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
    /// Room for one more byte: grow while the ring has not wrapped yet.
    /// (`room` keeps the decoder from writing over bytes not handed out.)
    fn makeRoom(s: *RingSink) Error!void {
        if (s.total == s.buf.len and s.buf.len < s.limit) {
            const new_len = @min(s.buf.len * 2, s.limit);
            s.buf = try s.gpa.realloc(s.buf, new_len);
            s.mask = new_len - 1;
        } else std.debug.assert(s.total - s.flushed < s.buf.len);
    }
    fn put(s: *RingSink, b: u8) Error!void {
        if (s.total - s.flushed == s.buf.len or s.total == s.buf.len) try s.makeRoom();
        s.buf[s.total & s.mask] = b;
        s.total += 1;
    }
    fn putSlice(s: *RingSink, bytes: []const u8) Error!void {
        for (bytes) |b| try s.put(b);
    }
    /// `back(d)` moves with every byte put, so an overlapping copy (d < n)
    /// repeats the pattern, as LZ77 requires.
    fn copyBack(s: *RingSink, d: usize, n: usize) Error!void {
        for (0..n) |_| try s.put(s.back(d));
    }
    fn hint(_: *RingSink, _: usize) void {}
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
        // A copy out of the prefix dictionary that runs on into the window
        // reaches back up to the window plus the dictionary.
        const prefix_len = if (prefixOf(s.options)) |px| px.len else |_| 0;
        const window = std.math.ceilPowerOfTwo(usize, (@as(usize, 1) << @intCast(wbits)) + prefix_len) catch return error.OutOfMemory;
        const cap_pow2 = std.math.ceilPowerOfTwo(usize, @max(s.options.max_output, 1)) catch window;
        s.limit = @min(window, cap_pow2);
        const len = @min(s.limit, initial_len);
        s.buf = try s.gpa.alloc(u8, len);
        s.mask = len - 1;
    }
    fn endMetablock(_: *RingSink) Error!void {}
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
    var d: Decompressor = .init(gpa, in, &.{}, options);
    defer d.deinit();
    while (true) {
        _ = d.reader.stream(out, .unlimited) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return d.err orelse error.ReadFailed,
            error.WriteFailed => return error.WriteFailed,
        };
    }
    try out.flush();
    return d.sink.total;
}

/// A pull `std.Io.Reader` over the decompressed bytes of one Brotli stream
/// read from `in` (SPEC.md backlog R9): reading from `reader` decodes as
/// much as it needs — the decoder stops mid-command when the window holds
/// nothing but bytes not read yet, and goes on at the next read. Memory and
/// limits as `decompressStream` (the window, the output cap with the input
/// consumed so far as the ratio's base), which is a loop over this.
///
/// A failure is `error.ReadFailed` from the reader, its cause in `err` — a
/// format error, or `ReadFailed` when `in` failed. At the end of the stream
/// the reader reports `EndOfStream` and `in` is left as `decompressStream`
/// leaves it.
pub const Decompressor = struct {
    /// The interface. Its buffer is the one passed to `init` (it may be
    /// empty: reads then stream straight from the window).
    reader: std.Io.Reader,
    /// Why the last `error.ReadFailed` came.
    err: ?Error = null,
    arena_state: std.heap.ArenaAllocator,
    br: BitReader,
    sink: RingSink,
    dec: DecoderOf(RingSink),
    done: bool = false,

    pub const Error = BrotliError || error{ReadFailed};

    /// `in` must have a non-empty buffer (as for `decompressStream`).
    pub fn init(gpa: std.mem.Allocator, in: *std.Io.Reader, buffer: []u8, options: Options) Decompressor {
        return .{
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .err = if (prefixOf(options)) |_| null else |e| e,
            .arena_state = .init(gpa),
            .br = .initStream(in),
            .sink = .{ .gpa = gpa, .options = options },
            .dec = .{
                .arena_state = undefined,
                .arena = undefined,
                .br = undefined,
                .out = undefined,
                .prefix = prefixOf(options) catch "", // refused through `err`, below
                .allow_large_window = options.large_window,
                .metadata = options.metadata,
                .shared = options.shared_dictionary,
            },
        };
    }

    pub fn deinit(d: *Decompressor) void {
        d.sink.deinit();
        d.arena_state.deinit();
        d.* = undefined;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const d: *Decompressor = @alignCast(@fieldParentPtr("reader", r));
        // The decoder's pointers into this struct, which may have moved
        // since `init`.
        d.dec.arena_state = &d.arena_state;
        d.dec.arena = d.arena_state.allocator();
        d.dec.br = &d.br;
        d.dec.out = &d.sink;
        while (true) {
            // After a failure, nothing more: not even what the failing
            // meta-block had produced (as `decompressStream` never wrote it).
            if (d.err != null) return error.ReadFailed;
            if (d.sink.unflushed() != 0) return d.sink.drain(w, limit);
            if (d.done) return error.EndOfStream;
            const progress = d.dec.step() catch |e| {
                d.err = if (e == error.TruncatedInput and d.br.read_failed) error.ReadFailed else e;
                return error.ReadFailed;
            };
            if (progress == .done) {
                d.done = true;
                d.br.finish();
            }
        }
    }
};

test "WBITS codes (RFC 7932 section 9.1)" {
    // The stream header: "0" is 16; "1" + 3 bits n != 0 is 17 + n; "1" + "000"
    // + 3 bits m is 17 for m = 0, invalid (large window) for m = 1, 8 + m
    // otherwise. Bits are listed in reading order, first bit first.
    const Case = struct { bits: []const u8, want: ?u6 };
    const cases = [_]Case{
        .{ .bits = "0", .want = 16 },
        .{ .bits = "1100", .want = 18 }, // n = 1 (3-bit field, LSB first: 100)
        .{ .bits = "1111", .want = 24 }, // n = 7
        .{ .bits = "1000000", .want = 17 },
        .{ .bits = "1000100", .want = null }, // m = 1
        .{ .bits = "1000010", .want = 10 }, // m = 2
        .{ .bits = "1000110", .want = 11 }, // m = 3
        .{ .bits = "1000111", .want = 15 }, // m = 7
    };
    for (cases) |c| {
        var byte = [_]u8{ 0, 0 };
        for (c.bits, 0..) |ch, i| {
            if (ch == '1') byte[i / 8] |= @as(u8, 1) << @intCast(i % 8);
        }
        var br = BitReader.init(&byte);
        if (c.want) |w| {
            try std.testing.expectEqual(w, (try decodeWindowBits(&br, false)).wbits);
        } else {
            try std.testing.expectError(error.InvalidWindowBits, decodeWindowBits(&br, false));
        }
    }
}
