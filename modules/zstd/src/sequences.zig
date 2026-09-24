// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Sequence store and sequence-section encoding.
//!
//! Ports `SeqStore_t` and friends (lib/compress/zstd_compress_internal.h), the
//! code tables of lib/common/zstd_internal.h, and the encoder of
//! lib/compress/zstd_compress_sequences.c (v1.5.7).
//!
//! Encoding-type selection follows both of libzstd's branches: below the
//! `lazy` strategy it picks by count heuristics, from `lazy` on it prices the
//! predefined table, the previous block's table and a fresh one. A
//! dictionary's tables start out `valid`: the heuristic branch then reuses
//! them for fewer than 1000 sequences.

const std = @import("std");
const bitstream = @import("bitstream.zig");
const fse = @import("fse.zig");
const hist = @import("hist.zig");

pub const Error = error{ DstSizeTooSmall, Generic };

pub const min_match = 3;
pub const rep_num = 3;
pub const max_ll = 35;
pub const max_ml = 52;
pub const max_off = 31;
pub const default_max_off = 28;
pub const ll_fse_log = 9;
pub const ml_fse_log = 9;
pub const off_fse_log = 8;
pub const long_nb_seq = 0x7F00;

pub const ll_bits = [max_ll + 1]u8{
    0,  0,  0,  0,  0, 0,  0,  0,
    0,  0,  0,  0,  0, 0,  0,  0,
    1,  1,  1,  1,  2, 2,  3,  3,
    4,  6,  7,  8,  9, 10, 11, 12,
    13, 14, 15, 16,
};
pub const ll_default_norm = [max_ll + 1]i16{
    4,  3,  2,  2,  2, 2, 2, 2,
    2,  2,  2,  2,  2, 1, 1, 1,
    2,  2,  2,  2,  2, 2, 2, 2,
    2,  3,  2,  1,  1, 1, 1, 1,
    -1, -1, -1, -1,
};
pub const ll_default_norm_log = 6;

pub const ml_bits = [max_ml + 1]u8{
    0,  0,  0,  0,  0,  0, 0,  0,
    0,  0,  0,  0,  0,  0, 0,  0,
    0,  0,  0,  0,  0,  0, 0,  0,
    0,  0,  0,  0,  0,  0, 0,  0,
    1,  1,  1,  1,  2,  2, 3,  3,
    4,  4,  5,  7,  8,  9, 10, 11,
    12, 13, 14, 15, 16,
};
pub const ml_default_norm = [max_ml + 1]i16{
    1,  4,  3,  2,  2,  2, 2,  2,
    2,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, -1, -1,
    -1, -1, -1, -1, -1,
};
pub const ml_default_norm_log = 6;

pub const of_default_norm = [default_max_off + 1]i16{
    1,  1,  1,  1,  1,  1, 2, 2,
    2,  1,  1,  1,  1,  1, 1, 1,
    1,  1,  1,  1,  1,  1, 1, 1,
    -1, -1, -1, -1, -1,
};
pub const of_default_norm_log = 5;

pub const SeqDef = struct {
    /// offset + rep_num, or repcode 1..3
    off_base: u32,
    lit_length: u16,
    /// match length - min_match
    ml_base: u16,
};

pub const LongLengthType = enum { none, literal_length, match_length };

pub const SeqStore = struct {
    seqs: []SeqDef,
    n_seq: usize = 0,
    lits: []u8,
    n_lit: usize = 0,
    ll_code: []u8,
    ml_code: []u8,
    of_code: []u8,
    long_length_type: LongLengthType = .none,
    long_length_pos: u32 = 0,

    pub fn reset(s: *SeqStore) void {
        s.n_seq = 0;
        s.n_lit = 0;
        s.long_length_type = .none;
    }

    /// `ZSTD_storeSeq`: copy `literals` and record one sequence.
    pub inline fn store(s: *SeqStore, literals: []const u8, off_base: u32, match_length: usize) void {
        @memcpy(s.lits[s.n_lit..][0..literals.len], literals);
        s.n_lit += literals.len;
        s.storeOnly(literals.len, off_base, match_length);
    }

    /// `ZSTD_storeSeqOnly`.
    pub inline fn storeOnly(s: *SeqStore, lit_length: usize, off_base: u32, match_length: usize) void {
        std.debug.assert(s.n_seq < s.seqs.len);
        if (lit_length > 0xFFFF) {
            std.debug.assert(s.long_length_type == .none);
            s.long_length_type = .literal_length;
            s.long_length_pos = @intCast(s.n_seq);
        }
        std.debug.assert(match_length >= min_match);
        const ml_base = match_length - min_match;
        if (ml_base > 0xFFFF) {
            std.debug.assert(s.long_length_type == .none);
            s.long_length_type = .match_length;
            s.long_length_pos = @intCast(s.n_seq);
        }
        s.seqs[s.n_seq] = .{
            .off_base = off_base,
            .lit_length = @truncate(lit_length),
            .ml_base = @truncate(ml_base),
        };
        s.n_seq += 1;
    }

    pub fn storeLastLiterals(s: *SeqStore, literals: []const u8) void {
        @memcpy(s.lits[s.n_lit..][0..literals.len], literals);
        s.n_lit += literals.len;
    }

    /// `ZSTD_seqToCodes`.
    pub fn toCodes(s: *SeqStore) void {
        for (s.seqs[0..s.n_seq], 0..) |sq, u| {
            s.ll_code[u] = @intCast(llCode(sq.lit_length));
            s.of_code[u] = @intCast(fse.highbit32(sq.off_base));
            s.ml_code[u] = @intCast(mlCode(sq.ml_base));
        }
        switch (s.long_length_type) {
            .none => {},
            .literal_length => s.ll_code[s.long_length_pos] = max_ll,
            .match_length => s.ml_code[s.long_length_pos] = max_ml,
        }
    }
};

const ll_code_table = [64]u8{
    0,  1,  2,  3,  4,  5,  6,  7,
    8,  9,  10, 11, 12, 13, 14, 15,
    16, 16, 17, 17, 18, 18, 19, 19,
    20, 20, 20, 20, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22,
    23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24,
};

pub fn llCode(lit_length: u32) u32 {
    return if (lit_length > 63) fse.highbit32(lit_length) + 19 else ll_code_table[lit_length];
}

const ml_code_table = [128]u8{
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
    38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
};

pub fn mlCode(ml_base: u32) u32 {
    return if (ml_base > 127) fse.highbit32(ml_base) + 36 else ml_code_table[ml_base];
}

pub const EncodingType = enum(u2) { basic = 0, rle = 1, compressed = 2, repeat = 3 };

/// `FSE_repeat`: `check` when the previous table may lack a symbol,
/// `valid` for a dictionary's table that has them all.
pub const FseRepeat = enum { none, check, valid };

/// The three sequence tables a block leaves behind for the next one.
pub const FseTables = struct {
    of: fse.CTable = .{},
    ml: fse.CTable = .{},
    ll: fse.CTable = .{},
    of_repeat: FseRepeat = .none,
    ml_repeat: FseRepeat = .none,
    ll_repeat: FseRepeat = .none,
};

/// `kInverseProbabilityLog256`: floor(-log2(x / 256) * 256), 0 for x = 0.
const inverse_probability_log256 = [256]u32{
    0,    2048, 1792, 1642, 1536, 1453, 1386, 1329, 1280, 1236, 1197, 1162,
    1130, 1100, 1073, 1047, 1024, 1001, 980,  960,  941,  923,  906,  889,
    874,  859,  844,  830,  817,  804,  791,  779,  768,  756,  745,  734,
    724,  714,  704,  694,  685,  676,  667,  658,  650,  642,  633,  626,
    618,  610,  603,  595,  588,  581,  574,  567,  561,  554,  548,  542,
    535,  529,  523,  517,  512,  506,  500,  495,  489,  484,  478,  473,
    468,  463,  458,  453,  448,  443,  438,  434,  429,  424,  420,  415,
    411,  407,  402,  398,  394,  390,  386,  382,  377,  373,  370,  366,
    362,  358,  354,  350,  347,  343,  339,  336,  332,  329,  325,  322,
    318,  315,  311,  308,  305,  302,  298,  295,  292,  289,  286,  282,
    279,  276,  273,  270,  267,  264,  261,  258,  256,  253,  250,  247,
    244,  241,  239,  236,  233,  230,  228,  225,  222,  220,  217,  215,
    212,  209,  207,  204,  202,  199,  197,  194,  192,  190,  187,  185,
    182,  180,  178,  175,  173,  171,  168,  166,  164,  162,  159,  157,
    155,  153,  151,  149,  146,  144,  142,  140,  138,  136,  134,  132,
    130,  128,  126,  123,  121,  119,  117,  115,  114,  112,  110,  108,
    106,  104,  102,  100,  98,   96,   94,   93,   91,   89,   87,   85,
    83,   82,   80,   78,   76,   74,   73,   71,   69,   67,   66,   64,
    62,   61,   59,   57,   55,   54,   52,   50,   49,   47,   46,   44,
    42,   41,   39,   37,   36,   34,   33,   31,   30,   28,   26,   25,
    23,   22,   20,   19,   17,   16,   14,   13,   11,   10,   8,    7,
    5,    4,    2,    1,
};

/// A cost libzstd reports as an error code: larger than every real cost.
pub const cost_error = std.math.maxInt(usize);

/// `ZSTD_NCountCost`: bytes of the table header a fresh table would need.
fn nCountCost(counts: []const u32, max: u32, n_seq: usize, fse_log: u32) Error!usize {
    var wksp: [512]u8 = undefined; // FSE_NCOUNTBOUND
    var norm: [max_ml + 1]i16 = undefined;
    const table_log = fse.optimalTableLog(fse_log, n_seq, max);
    _ = try fse.normalizeCount(&norm, table_log, counts, n_seq, max, n_seq >= 2048);
    return fse.writeNCount(&wksp, &norm, max, table_log);
}

/// `ZSTD_entropyCost`: bits to code `counts` at the entropy bound.
fn entropyCost(counts: []const u32, max: u32, total: usize) usize {
    var cost: usize = 0;
    for (counts[0 .. max + 1]) |c| {
        var norm: usize = (256 * @as(usize, c)) / total;
        if (c != 0 and norm == 0) norm = 1;
        cost += c * inverse_probability_log256[norm];
    }
    return cost >> 8;
}

/// `ZSTD_fseBitCost`: bits to code `counts` with `ct`, or `cost_error` when
/// `ct` cannot represent one of the symbols.
pub fn fseBitCost(ct: *const fse.CTable, counts: []const u32, max: u32) usize {
    const accuracy_log = 8;
    if (ct.max_symbol < max) return cost_error;
    const table_log = ct.table_log;
    const table_size: u32 = @as(u32, 1) << @intCast(table_log);
    var cost: usize = 0;
    for (counts[0 .. max + 1], 0..) |c, s| {
        if (c == 0) continue;
        // FSE_bitCost
        const delta_nb_bits = ct.symbol_tt[s].delta_nb_bits;
        const min_nb_bits = delta_nb_bits >> 16;
        const threshold = (min_nb_bits + 1) << 16;
        const delta_from_threshold = threshold -% (delta_nb_bits +% table_size);
        const normalized_delta = (delta_from_threshold << accuracy_log) >> @intCast(table_log);
        const bit_cost = (min_nb_bits + 1) * (1 << accuracy_log) -% normalized_delta;
        const bad_cost = (table_log + 1) << accuracy_log;
        if (bit_cost >= bad_cost) return cost_error; // Prob[s] == 0
        cost += @as(usize, c) * bit_cost;
    }
    return cost >> accuracy_log;
}

/// `ZSTD_crossEntropyCost`: bits to code `counts` with the table `norm`.
pub fn crossEntropyCost(norm: []const i16, accuracy_log: u32, counts: []const u32, max: u32) usize {
    const shift: u5 = @intCast(8 - accuracy_log);
    var cost: usize = 0;
    for (counts[0 .. max + 1], norm[0 .. max + 1]) |c, n| {
        const norm_acc: u32 = if (n != -1) @intCast(n) else 1;
        cost += c * inverse_probability_log256[norm_acc << shift];
    }
    return cost >> 8;
}

/// `ZSTD_selectEncodingType`.
fn selectEncodingType(repeat_mode: *FseRepeat, counts: []const u32, max: u32, most_frequent: usize, n_seq: usize, fse_log: u32, prev: *const fse.CTable, default_norm: []const i16, default_norm_log: u32, default_allowed: bool, strategy: u32) Error!EncodingType {
    if (most_frequent == n_seq) {
        repeat_mode.* = .none;
        // set_basic codes 2 or fewer symbols in fewer bits than RLE's byte
        if (default_allowed and n_seq <= 2) return .basic;
        return .rle;
    }
    if (strategy < 4) { // below ZSTD_lazy
        if (default_allowed) {
            const mult = 10 - strategy;
            const base_log = 3;
            const dynamic_fse_nb_seq_min = ((@as(usize, 1) << @intCast(default_norm_log)) * mult) >> base_log;
            const static_fse_nb_seq_max = 1000;
            if (repeat_mode.* == .valid and n_seq < static_fse_nb_seq_max) return .repeat;
            if (n_seq < dynamic_fse_nb_seq_min or most_frequent < (n_seq >> @intCast(default_norm_log - 1))) {
                repeat_mode.* = .none;
                return .basic;
            }
        }
    } else {
        const basic_cost = if (default_allowed) crossEntropyCost(default_norm, default_norm_log, counts, max) else cost_error;
        const repeat_cost = if (repeat_mode.* != .none) fseBitCost(prev, counts, max) else cost_error;
        const n_count_cost = try nCountCost(counts, max, n_seq, fse_log);
        const compressed_cost = (n_count_cost << 3) + entropyCost(counts, max, n_seq);
        if (basic_cost <= repeat_cost and basic_cost <= compressed_cost) {
            std.debug.assert(default_allowed);
            repeat_mode.* = .none;
            return .basic;
        }
        if (repeat_cost <= compressed_cost) return .repeat;
    }
    repeat_mode.* = .check;
    return .compressed;
}

/// `ZSTD_buildCTable`: build `next` for `kind` and write its header (if any).
fn buildCTable(dst: []u8, next: *fse.CTable, prev: *const fse.CTable, fse_log: u32, kind: EncodingType, counts: []u32, max: u32, codes: []const u8, default_norm: []const i16, default_norm_log: u32, default_max: u32) Error!usize {
    switch (kind) {
        .rle => {
            next.buildRle(@intCast(max));
            if (dst.len == 0) return error.DstSizeTooSmall;
            dst[0] = codes[0];
            return 1;
        },
        .repeat => {
            next.* = prev.*;
            return 0;
        },
        .basic => {
            try next.build(default_norm, default_max, default_norm_log);
            return 0;
        },
        .compressed => {
            var norm: [max_ml + 1]i16 = undefined;
            var n_seq_1 = codes.len;
            const table_log = fse.optimalTableLog(fse_log, codes.len, max);
            // The last code is emitted as the initial state; its count does not
            // need to be representable, so drop one occurrence when possible.
            if (counts[codes[codes.len - 1]] > 1) {
                counts[codes[codes.len - 1]] -= 1;
                n_seq_1 -= 1;
            }
            _ = try fse.normalizeCount(&norm, table_log, counts, n_seq_1, max, n_seq_1 >= 2048);
            const n_count_size = try fse.writeNCount(dst, &norm, max, table_log);
            try next.build(&norm, max, table_log);
            return n_count_size;
        },
    }
}

pub const Stats = struct {
    ll_type: EncodingType,
    of_type: EncodingType,
    ml_type: EncodingType,
    size: usize,
    /// Size of the last `compressed` table header (the zstd <= 1.3.4 workaround).
    last_count_size: usize,
};

/// `ZSTD_buildSequencesStatistics`: choose and build the three tables, writing
/// their headers into `dst`.
pub fn buildStatistics(ss: *SeqStore, prev: *const FseTables, next: *FseTables, dst: []u8, strategy: u32) Error!Stats {
    const n_seq = ss.n_seq;
    std.debug.assert(n_seq != 0);
    ss.toCodes();
    var counts: [max_ml + 1]u32 = undefined;
    var op: usize = 0;
    var stats: Stats = .{ .ll_type = .basic, .of_type = .basic, .ml_type = .basic, .size = 0, .last_count_size = 0 };

    // literal lengths
    {
        var max: u32 = max_ll;
        const most_frequent = hist.count(&counts, &max, ss.ll_code[0..n_seq]);
        next.ll_repeat = prev.ll_repeat;
        stats.ll_type = try selectEncodingType(&next.ll_repeat, &counts, max, most_frequent, n_seq, ll_fse_log, &prev.ll, &ll_default_norm, ll_default_norm_log, true, strategy);
        const count_size = try buildCTable(dst[op..], &next.ll, &prev.ll, ll_fse_log, stats.ll_type, &counts, max, ss.ll_code[0..n_seq], &ll_default_norm, ll_default_norm_log, max_ll);
        if (stats.ll_type == .compressed) stats.last_count_size = count_size;
        op += count_size;
    }
    // offsets
    {
        var max: u32 = max_off;
        const most_frequent = hist.count(&counts, &max, ss.of_code[0..n_seq]);
        // The predefined table only reaches code 28.
        const default_allowed = max <= default_max_off;
        next.of_repeat = prev.of_repeat;
        stats.of_type = try selectEncodingType(&next.of_repeat, &counts, max, most_frequent, n_seq, off_fse_log, &prev.of, &of_default_norm, of_default_norm_log, default_allowed, strategy);
        const count_size = try buildCTable(dst[op..], &next.of, &prev.of, off_fse_log, stats.of_type, &counts, max, ss.of_code[0..n_seq], &of_default_norm, of_default_norm_log, default_max_off);
        if (stats.of_type == .compressed) stats.last_count_size = count_size;
        op += count_size;
    }
    // match lengths
    {
        var max: u32 = max_ml;
        const most_frequent = hist.count(&counts, &max, ss.ml_code[0..n_seq]);
        next.ml_repeat = prev.ml_repeat;
        stats.ml_type = try selectEncodingType(&next.ml_repeat, &counts, max, most_frequent, n_seq, ml_fse_log, &prev.ml, &ml_default_norm, ml_default_norm_log, true, strategy);
        const count_size = try buildCTable(dst[op..], &next.ml, &prev.ml, ml_fse_log, stats.ml_type, &counts, max, ss.ml_code[0..n_seq], &ml_default_norm, ml_default_norm_log, max_ml);
        if (stats.ml_type == .compressed) stats.last_count_size = count_size;
        op += count_size;
    }
    stats.size = op;
    return stats;
}

/// `ZSTD_encodeSequences` (64-bit accumulator schedule).
pub fn encode(dst: []u8, ss: *const SeqStore, ct_ml: *const fse.CTable, ct_of: *const fse.CTable, ct_ll: *const fse.CTable) Error!usize {
    var bits = bitstream.CStream.init(dst) catch return error.DstSizeTooSmall;
    const n_seq = ss.n_seq;
    const seqs = ss.seqs;
    const last = n_seq - 1;

    var st_ml = fse.CState.init2(ct_ml, ss.ml_code[last]);
    var st_of = fse.CState.init2(ct_of, ss.of_code[last]);
    var st_ll = fse.CState.init2(ct_ll, ss.ll_code[last]);
    bits.addBits(seqs[last].lit_length, ll_bits[ss.ll_code[last]]);
    bits.addBits(seqs[last].ml_base, ml_bits[ss.ml_code[last]]);
    bits.addBits(seqs[last].off_base, ss.of_code[last]);
    bits.flush();

    var n: usize = last;
    while (n > 0) {
        n -= 1;
        const ll_c = ss.ll_code[n];
        const of_c = ss.of_code[n];
        const ml_c = ss.ml_code[n];
        const llb: u32 = ll_bits[ll_c];
        const ofb: u32 = of_c;
        const mlb: u32 = ml_bits[ml_c];
        st_of.encode(&bits, of_c); // 15
        st_ml.encode(&bits, ml_c); // 24
        st_ll.encode(&bits, ll_c); // 16
        if (ofb + mlb + llb >= 64 - 7 - (ll_fse_log + ml_fse_log + off_fse_log)) bits.flush();
        bits.addBits(seqs[n].lit_length, llb);
        bits.addBits(seqs[n].ml_base, mlb);
        if (ofb + mlb + llb > 56) bits.flush();
        bits.addBits(seqs[n].off_base, ofb);
        bits.flush();
    }

    st_ml.flushState(&bits);
    st_of.flushState(&bits);
    st_ll.flushState(&bits);
    const stream_size = bits.close();
    if (stream_size == 0) return error.DstSizeTooSmall;
    return stream_size;
}

test "length codes match the format tables" {
    try std.testing.expectEqual(@as(u32, 15), llCode(15));
    try std.testing.expectEqual(@as(u32, 16), llCode(16));
    try std.testing.expectEqual(@as(u32, 24), llCode(63));
    try std.testing.expectEqual(@as(u32, 25), llCode(64));
    try std.testing.expectEqual(@as(u32, 35), llCode(65536));
    try std.testing.expectEqual(@as(u32, 31), mlCode(31));
    try std.testing.expectEqual(@as(u32, 32), mlCode(32));
    try std.testing.expectEqual(@as(u32, 42), mlCode(127));
    try std.testing.expectEqual(@as(u32, 43), mlCode(128));
}

test "default distributions agree with the decoder in std" {
    const z = std.compress.zstd;
    try std.testing.expectEqualSlices(i16, &z.literals_length_default_distribution, &ll_default_norm);
    try std.testing.expectEqualSlices(i16, &z.match_lengths_default_distribution, &ml_default_norm);
    try std.testing.expectEqualSlices(i16, &z.offset_codes_default_distribution, &of_default_norm);
}
