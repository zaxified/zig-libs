// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Block decoder: literals section, sequences section (FSE tables, the
//! sequence bitstream, repeat offsets) and sequence execution against the
//! history.
//!
//! Port of lib/decompress/zstd_decompress_block.c (v1.5.7), 64-bit paths.
//! Deliberate simplifications, none of which changes a decoded byte:
//! - literals always live in the context's own buffer (or in the source,
//!   for raw literals with room behind them), never inside `dst` — libzstd
//!   parks them at the far end of `dst` when it can, to save a copy;
//! - only the "short" sequence decoder is ported; libzstd switches to the
//!   prefetching one for cold dictionaries and long distances, which
//!   executes the same sequences in the same order.
//! On corrupt input either choice can change which error is reported (not
//! whether one is): the prefetching decoder checks the end of the bitstream
//! before executing its last eight sequences.

const std = @import("std");
const dbits = @import("dbits.zig");
const huf = @import("huf_dec.zig");
const seqs = @import("sequences.zig");
const DStream = dbits.DStream;
const readLE16 = dbits.readLE16;
const readLE24 = dbits.readLE24;
const readLE32 = dbits.readLE32;

pub const Error = error{
    CorruptionDetected,
    SrcSizeWrong,
    DstSizeTooSmall,
    DictionaryCorrupted,
    LiteralsHeaderWrong,
};

pub const block_size_max = 128 * 1024;
pub const wildcopy_overlength = 32;
const wildcopy_veclen = 16;
const min_cblock_size = 2;
const min_literals_for_4_streams = 6;
const long_nb_seq = 0x7F00;

pub const max_ll = seqs.max_ll;
pub const max_ml = seqs.max_ml;
pub const max_off = seqs.max_off;
pub const ll_fse_log = seqs.ll_fse_log;
pub const ml_fse_log = seqs.ml_fse_log;
pub const off_fse_log = seqs.off_fse_log;
const max_seq = @max(max_ll, max_ml);
const max_fse_log = 9;

pub const ll_base = [max_ll + 1]u32{
    0,      1,      2,      3,       4,     5,     6,     7,
    8,      9,      10,     11,      12,    13,    14,    15,
    16,     18,     20,     22,      24,    28,    32,    40,
    48,     64,     0x80,   0x100,   0x200, 0x400, 0x800, 0x1000,
    0x2000, 0x4000, 0x8000, 0x10000,
};

pub const of_base = [max_off + 1]u32{
    0,        1,         1,         5,         0xD,       0x1D,       0x3D,       0x7D,
    0xFD,     0x1FD,     0x3FD,     0x7FD,     0xFFD,     0x1FFD,     0x3FFD,     0x7FFD,
    0xFFFD,   0x1FFFD,   0x3FFFD,   0x7FFFD,   0xFFFFD,   0x1FFFFD,   0x3FFFFD,   0x7FFFFD,
    0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
};

pub const of_bits = blk: {
    var b: [max_off + 1]u8 = undefined;
    for (&b, 0..) |*v, i| v.* = i;
    break :blk b;
};

pub const ml_base = [max_ml + 1]u32{
    3,      4,      5,      6,      7,       8,     9,     10,
    11,     12,     13,     14,     15,      16,    17,    18,
    19,     20,     21,     22,     23,      24,    25,    26,
    27,     28,     29,     30,     31,      32,    33,    34,
    35,     37,     39,     41,     43,      47,    51,    59,
    67,     83,     99,     0x83,   0x103,   0x203, 0x403, 0x803,
    0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
};

/// `ZSTD_seqSymbol`.
pub const SeqSymbol = extern struct {
    next_state: u16,
    nb_additional_bits: u8,
    nb_bits: u8,
    base_value: u32,
};

/// A sequence decoding table, header fields included; sized for the
/// largest (log 9) so one type serves all three codes.
pub const SeqTable = struct {
    table_log: u32 = 0,
    cells: [1 << max_fse_log]SeqSymbol = undefined,
};

/// `ZSTD_buildFSETable_body`.
pub fn buildFseTable(dt: *SeqTable, norm: []const i16, max_sv: u32, base: []const u32, nb_add: []const u8, table_log: u32) void {
    const max_sv1 = max_sv + 1;
    const table_size: u32 = @as(u32, 1) << @intCast(table_log);
    var symbol_next: [max_seq + 1]u16 = undefined;
    var spread: [(1 << max_fse_log) + 8]u8 = undefined;
    var high_threshold: u32 = table_size - 1;
    const cells = &dt.cells;

    dt.table_log = table_log;
    {
        var s: u32 = 0;
        while (s < max_sv1) : (s += 1) {
            if (norm[s] == -1) {
                cells[high_threshold].base_value = s;
                high_threshold -%= 1;
                symbol_next[s] = 1;
            } else {
                symbol_next[s] = @intCast(norm[s]);
            }
        }
    }

    if (high_threshold == table_size - 1) {
        const table_mask = table_size - 1;
        const step = dbits.tableStep(table_size);
        var pos: usize = 0;
        var s: u32 = 0;
        while (s < max_sv1) : (s += 1) {
            const n: usize = @intCast(norm[s]);
            @memset(spread[pos..][0..n], @intCast(s));
            pos += n;
        }
        var position: u32 = 0;
        var i: u32 = 0;
        while (i < table_size) : (i += 1) {
            cells[position].base_value = spread[i];
            position = (position + step) & table_mask;
        }
    } else {
        const table_mask = table_size - 1;
        const step = dbits.tableStep(table_size);
        var position: u32 = 0;
        var s: u32 = 0;
        while (s < max_sv1) : (s += 1) {
            var i: i32 = 0;
            while (i < norm[s]) : (i += 1) {
                cells[position].base_value = s;
                position = (position + step) & table_mask;
                while (position > high_threshold) position = (position + step) & table_mask;
            }
        }
    }

    var u: u32 = 0;
    while (u < table_size) : (u += 1) {
        const symbol = cells[u].base_value;
        const next_state: u32 = symbol_next[symbol];
        symbol_next[symbol] += 1;
        const nb: u32 = table_log - dbits.highbit32(next_state);
        cells[u].nb_bits = @intCast(nb);
        cells[u].next_state = @truncate((next_state << @intCast(nb)) -% table_size);
        cells[u].nb_additional_bits = nb_add[symbol];
        cells[u].base_value = base[symbol];
    }
}

fn defaultTable(comptime norm: []const i16, comptime max_sv: u32, comptime base: []const u32, comptime nb_add: []const u8, comptime log: u32) SeqTable {
    @setEvalBranchQuota(100_000);
    var t: SeqTable = .{};
    buildFseTable(&t, norm, max_sv, base, nb_add, log);
    return t;
}

pub const ll_default: SeqTable = defaultTable(&seqs.ll_default_norm, max_ll, &ll_base, &seqs.ll_bits, seqs.ll_default_norm_log);
pub const of_default: SeqTable = defaultTable(&seqs.of_default_norm, seqs.default_max_off, &of_base, &of_bits, seqs.of_default_norm_log);
pub const ml_default: SeqTable = defaultTable(&seqs.ml_default_norm, max_ml, &ml_base, &seqs.ml_bits, seqs.ml_default_norm_log);

/// The decoding state a block needs from its frame: entropy tables that
/// carry over between blocks, repeat offsets, and the literals of the
/// current block.
pub const State = struct {
    ll: SeqTable = .{},
    of: SeqTable = .{},
    ml: SeqTable = .{},
    huf: huf.DTable = .{},
    rep: [3]u32 = .{ 1, 4, 8 },
    ll_ptr: *const SeqTable = &ll_default,
    of_ptr: *const SeqTable = &of_default,
    ml_ptr: *const SeqTable = &ml_default,
    huf_ptr: *const huf.DTable = undefined,
    lit_entropy: bool = false,
    fse_entropy: bool = false,
    /// `fParams.blockSizeMax` of the frame being decoded.
    block_size_max: usize = block_size_max,

    /// The current block's literals: `lit_src[lit_pos..lit_end]`, with at
    /// least `wildcopy_overlength` readable bytes behind `lit_end`.
    lit_src: []const u8 = &.{},
    lit_pos: usize = 0,
    lit_end: usize = 0,
    lit_buf: [block_size_max + wildcopy_overlength]u8 = undefined,

    /// `ZSTD_decompressBegin`'s part of the reset.
    pub fn begin(st: *State) void {
        st.huf.max_table_log = huf.tablelog_max;
        st.huf.table_type = 0;
        st.huf.table_log = 0;
        st.lit_entropy = false;
        st.fse_entropy = false;
        st.rep = .{ 1, 4, 8 };
        st.ll_ptr = &st.ll;
        st.of_ptr = &st.of;
        st.ml_ptr = &st.ml;
        st.huf_ptr = &st.huf;
    }
};

// ---------------------------------------------------------------- literals

/// `ZSTD_decodeLiteralsBlock`. `dst_capacity` is the room left in the
/// output. Returns the size of the literals section.
fn decodeLiterals(st: *State, src: []const u8, dst_capacity: usize) Error!usize {
    if (src.len < min_cblock_size) return error.CorruptionDetected;
    const lit_enc_type = src[0] & 3;
    const bsm = st.block_size_max;
    const expected_write_size = @min(bsm, dst_capacity);
    switch (lit_enc_type) {
        3, 2 => { // set_repeat, set_compressed
            if (lit_enc_type == 3 and !st.lit_entropy) return error.DictionaryCorrupted;
            if (src.len < 5) return error.CorruptionDetected;
            const lhl_code = (src[0] >> 2) & 3;
            const lhc = readLE32(src, 0);
            var single_stream = false;
            var lh_size: usize = undefined;
            var lit_size: usize = undefined;
            var lit_c_size: usize = undefined;
            switch (lhl_code) {
                0, 1 => {
                    single_stream = lhl_code == 0;
                    lh_size = 3;
                    lit_size = (lhc >> 4) & 0x3FF;
                    lit_c_size = (lhc >> 14) & 0x3FF;
                },
                2 => {
                    lh_size = 4;
                    lit_size = (lhc >> 4) & 0x3FFF;
                    lit_c_size = lhc >> 18;
                },
                else => {
                    lh_size = 5;
                    lit_size = (lhc >> 4) & 0x3FFFF;
                    lit_c_size = (lhc >> 22) + (@as(usize, src[4]) << 10);
                },
            }
            if (lit_size > bsm) return error.CorruptionDetected;
            if (!single_stream and lit_size < min_literals_for_4_streams) return error.LiteralsHeaderWrong;
            if (lit_c_size + lh_size > src.len) return error.CorruptionDetected;
            if (expected_write_size < lit_size) return error.DstSizeTooSmall;

            const out = st.lit_buf[0..lit_size];
            const in = src[lh_size..][0..lit_c_size];
            const r = if (lit_enc_type == 3)
                (if (single_stream) huf.decompress1XUsing(st.huf_ptr, out, in) else huf.decompress4XUsing(st.huf_ptr, out, in))
            else if (single_stream)
                huf.decompress1X1Table(&st.huf, out, in)
            else
                huf.decompress4XTable(&st.huf, out, in);
            r catch return error.CorruptionDetected;

            st.lit_src = &st.lit_buf;
            st.lit_pos = 0;
            st.lit_end = lit_size;
            st.lit_entropy = true;
            if (lit_enc_type == 2) st.huf_ptr = &st.huf;
            return lit_c_size + lh_size;
        },
        0 => { // set_basic
            const lhl_code = (src[0] >> 2) & 3;
            var lh_size: usize = undefined;
            var lit_size: usize = undefined;
            switch (lhl_code) {
                0, 2 => {
                    lh_size = 1;
                    lit_size = src[0] >> 3;
                },
                1 => {
                    lh_size = 2;
                    lit_size = readLE16(src, 0) >> 4;
                },
                else => {
                    lh_size = 3;
                    if (src.len < 3) return error.CorruptionDetected;
                    lit_size = readLE24(src, 0) >> 4;
                },
            }
            if (lit_size > bsm) return error.CorruptionDetected;
            if (expected_write_size < lit_size) return error.DstSizeTooSmall;
            if (lh_size + lit_size + wildcopy_overlength > src.len) {
                // risk reading beyond src buffer with wildcopy
                if (lit_size + lh_size > src.len) return error.CorruptionDetected;
                @memcpy(st.lit_buf[0..lit_size], src[lh_size..][0..lit_size]);
                st.lit_src = &st.lit_buf;
                st.lit_pos = 0;
                st.lit_end = lit_size;
                return lh_size + lit_size;
            }
            // direct reference into compressed stream
            st.lit_src = src;
            st.lit_pos = lh_size;
            st.lit_end = lh_size + lit_size;
            return lh_size + lit_size;
        },
        else => { // set_rle
            const lhl_code = (src[0] >> 2) & 3;
            var lh_size: usize = undefined;
            var lit_size: usize = undefined;
            switch (lhl_code) {
                0, 2 => {
                    lh_size = 1;
                    lit_size = src[0] >> 3;
                },
                1 => {
                    lh_size = 2;
                    if (src.len < 3) return error.CorruptionDetected;
                    lit_size = readLE16(src, 0) >> 4;
                },
                else => {
                    lh_size = 3;
                    if (src.len < 4) return error.CorruptionDetected;
                    lit_size = readLE24(src, 0) >> 4;
                },
            }
            if (lit_size > bsm) return error.CorruptionDetected;
            if (expected_write_size < lit_size) return error.DstSizeTooSmall;
            @memset(st.lit_buf[0..lit_size], src[lh_size]);
            st.lit_src = &st.lit_buf;
            st.lit_pos = 0;
            st.lit_end = lit_size;
            return lh_size + 1;
        },
    }
}

// ---------------------------------------------------------------- sequences header

const EncType = enum(u2) { basic = 0, rle = 1, compressed = 2, repeat = 3 };

/// `ZSTD_buildSeqTable`. Returns the header bytes consumed.
fn buildSeqTable(space: *SeqTable, ptr: **const SeqTable, t: EncType, max_in: u32, max_log: u32, src: []const u8, base: []const u32, nb_add: []const u8, default: *const SeqTable, repeat_ok: bool) Error!usize {
    switch (t) {
        .rle => {
            if (src.len == 0) return error.SrcSizeWrong;
            if (src[0] > max_in) return error.CorruptionDetected;
            const symbol = src[0];
            space.table_log = 0;
            space.cells[0] = .{ .next_state = 0, .nb_additional_bits = nb_add[symbol], .nb_bits = 0, .base_value = base[symbol] };
            ptr.* = space;
            return 1;
        },
        .basic => {
            ptr.* = default;
            return 0;
        },
        .repeat => {
            if (!repeat_ok) return error.CorruptionDetected;
            return 0;
        },
        .compressed => {
            var norm: [max_seq + 1]i16 = undefined;
            var max = max_in;
            var table_log: u32 = undefined;
            const header_size = dbits.readNCount(&norm, &max, &table_log, src) catch return error.CorruptionDetected;
            if (table_log > max_log) return error.CorruptionDetected;
            buildFseTable(space, &norm, max, base, nb_add, table_log);
            ptr.* = space;
            return header_size;
        },
    }
}

/// `ZSTD_decodeSeqHeaders`. Returns the header size; `nb_seq` is set.
fn decodeSeqHeaders(st: *State, nb_seq: *u32, src: []const u8) Error!usize {
    const iend = src.len;
    var ip: usize = 0;
    if (src.len < 1) return error.SrcSizeWrong;
    var n: u32 = src[ip];
    ip += 1;
    if (n > 0x7F) {
        if (n == 0xFF) {
            if (ip + 2 > iend) return error.SrcSizeWrong;
            n = @as(u32, readLE16(src, ip)) + long_nb_seq;
            ip += 2;
        } else {
            if (ip >= iend) return error.SrcSizeWrong;
            n = ((n - 0x80) << 8) + src[ip];
            ip += 1;
        }
    }
    nb_seq.* = n;
    if (n == 0) {
        // no sequence: the section must end here
        if (ip != iend) return error.CorruptionDetected;
        return ip;
    }

    if (ip + 1 > iend) return error.SrcSizeWrong;
    if (src[ip] & 3 != 0) return error.CorruptionDetected; // reserved bits
    const ll_type: EncType = @enumFromInt(src[ip] >> 6);
    const of_type: EncType = @enumFromInt((src[ip] >> 4) & 3);
    const ml_type: EncType = @enumFromInt((src[ip] >> 2) & 3);
    ip += 1;

    ip += buildSeqTable(&st.ll, &st.ll_ptr, ll_type, max_ll, ll_fse_log, src[ip..], &ll_base, &seqs.ll_bits, &ll_default, st.fse_entropy) catch return error.CorruptionDetected;
    ip += buildSeqTable(&st.of, &st.of_ptr, of_type, max_off, off_fse_log, src[ip..], &of_base, &of_bits, &of_default, st.fse_entropy) catch return error.CorruptionDetected;
    ip += buildSeqTable(&st.ml, &st.ml_ptr, ml_type, max_ml, ml_fse_log, src[ip..], &ml_base, &seqs.ml_bits, &ml_default, st.fse_entropy) catch return error.CorruptionDetected;
    return ip;
}

// ---------------------------------------------------------------- sequence decoding

const Seq = struct { lit_length: usize, match_length: usize, offset: usize };

const FseState = struct {
    state: usize,
    table: *const SeqTable,

    inline fn init(d: *DStream, t: *const SeqTable) FseState {
        const s = d.readBits(t.table_log);
        _ = d.reload();
        return .{ .state = @intCast(s), .table = t };
    }
};

const SeqState = struct {
    d: DStream,
    ll: FseState,
    of: FseState,
    ml: FseState,
    prev: [3]usize,
};

/// `ZSTD_decodeSequence`, 64-bit.
inline fn decodeSequence(ss: *SeqState, is_last: bool) Seq {
    const ll_info = ss.ll.table.cells[ss.ll.state];
    const ml_info = ss.ml.table.cells[ss.ml.state];
    const of_info = ss.of.table.cells[ss.of.state];
    var seq: Seq = .{ .lit_length = ll_info.base_value, .match_length = ml_info.base_value, .offset = undefined };
    const of_base_v = of_info.base_value;
    const ll_bits_n: u32 = ll_info.nb_additional_bits;
    const ml_bits_n: u32 = ml_info.nb_additional_bits;
    const of_bits_n: u32 = of_info.nb_additional_bits;
    const total_bits: u32 = (ll_bits_n + ml_bits_n + of_bits_n) & 0xFF;

    var offset: usize = undefined;
    if (of_bits_n > 1) {
        offset = of_base_v + @as(usize, @intCast(ss.d.readBitsFast(of_bits_n)));
        ss.prev[2] = ss.prev[1];
        ss.prev[1] = ss.prev[0];
        ss.prev[0] = offset;
    } else {
        const ll0: usize = @intFromBool(ll_info.base_value == 0);
        if (of_bits_n == 0) {
            offset = ss.prev[ll0];
            ss.prev[1] = ss.prev[ll0 ^ 1];
            ss.prev[0] = offset;
        } else {
            offset = of_base_v + ll0 + @as(usize, @intCast(ss.d.readBitsFast(1)));
            var temp: usize = if (offset == 3) ss.prev[0] -% 1 else ss.prev[offset];
            temp -%= @intFromBool(temp == 0); // 0 is not valid: corrupted input
            if (offset != 1) ss.prev[2] = ss.prev[1];
            ss.prev[1] = ss.prev[0];
            ss.prev[0] = temp;
            offset = temp;
        }
    }
    seq.offset = offset;

    if (ml_bits_n > 0) seq.match_length += @intCast(ss.d.readBitsFast(ml_bits_n));
    if (total_bits >= 57 - (ll_fse_log + ml_fse_log + off_fse_log)) _ = ss.d.reload();
    if (ll_bits_n > 0) seq.lit_length += @intCast(ss.d.readBitsFast(ll_bits_n));

    if (!is_last) {
        ss.ll.state = ll_info.next_state + @as(usize, @intCast(ss.d.readBits(ll_info.nb_bits)));
        ss.ml.state = ml_info.next_state + @as(usize, @intCast(ss.d.readBits(ml_info.nb_bits)));
        ss.of.state = of_info.next_state + @as(usize, @intCast(ss.d.readBits(of_info.nb_bits)));
        _ = ss.d.reload();
    }
    return seq;
}

// ---------------------------------------------------------------- execution

/// Where a block writes and what it may reach back into: `out[prefix..]`
/// is this frame's contiguous output so far, `ext` the older segment
/// (dictionary content) that logically sits just before `out[prefix]`.
pub const History = struct {
    out: []u8,
    prefix: usize,
    ext: []const u8 = &.{},
};

inline fn copy8(out: []u8, op: usize, src: []const u8, ip: usize) void {
    @memcpy(out[op..][0..8], src[ip..][0..8]);
}
inline fn copy16(out: []u8, op: usize, src: []const u8, ip: usize) void {
    @memcpy(out[op..][0..16], src[ip..][0..16]);
}

/// `ZSTD_wildcopy`, no overlap: `src` and `out` are different buffers or
/// at least 16 bytes apart. May write up to 32 bytes past `op + length`.
inline fn wildcopyNoOverlap(out: []u8, op_in: usize, src: []const u8, ip_in: usize, length: usize) void {
    var op = op_in;
    var ip = ip_in;
    const oend = op + length;
    copy16(out, op, src, ip);
    if (16 >= length) return;
    op += 16;
    ip += 16;
    while (true) {
        copy16(out, op, src, ip);
        op += 16;
        ip += 16;
        copy16(out, op, src, ip);
        op += 16;
        ip += 16;
        if (op >= oend) break;
    }
}

/// `ZSTD_wildcopy` within `out`, source before destination.
inline fn wildcopyOverlap(out: []u8, op_in: usize, ip_in: usize, length: usize) void {
    const diff = op_in - ip_in;
    if (diff < wildcopy_veclen) {
        var op = op_in;
        var ip = ip_in;
        const oend = op + length;
        while (true) {
            std.mem.copyForwards(u8, out[op..][0..8], out[ip..][0..8]);
            op += 8;
            ip += 8;
            if (op >= oend) break;
        }
    } else {
        wildcopyNoOverlap(out, op_in, out, ip_in, length);
    }
}

/// `ZSTD_overlapCopy8`: copies 8 bytes from `ip` to `op` (offset < 8 may
/// overlap), then moves `ip` so that `op - ip >= 8` with the same pattern.
inline fn overlapCopy8(out: []u8, op: *usize, ip: *usize, offset: usize) void {
    if (offset < 8) {
        const dec32 = [8]u32{ 0, 1, 2, 1, 4, 4, 4, 4 };
        const dec64 = [8]i32{ 8, 8, 8, 7, 8, 9, 10, 11 };
        const sub2: usize = @intCast(dec64[offset]);
        out[op.* + 0] = out[ip.* + 0];
        out[op.* + 1] = out[ip.* + 1];
        out[op.* + 2] = out[ip.* + 2];
        out[op.* + 3] = out[ip.* + 3];
        ip.* += dec32[offset];
        std.mem.copyForwards(u8, out[op.* + 4 ..][0..4], out[ip.*..][0..4]);
        // C steps back by sub2 and then forward by 8; the pointer may dip
        // below the buffer in between, an index may not
        ip.* = ip.* + 8 - sub2;
    } else {
        std.mem.copyForwards(u8, out[op.*..][0..8], out[ip.*..][0..8]);
        ip.* += 8;
    }
    op.* += 8;
}

inline fn sle(a: usize, b: isize) bool {
    return @as(isize, @intCast(a)) <= b;
}

/// `ZSTD_safecopy`, source in `out` before `op` (overlap allowed).
fn safecopyOverlap(out: []u8, op_in: usize, oend_w: isize, ip_in: usize, length_in: usize) void {
    var op = op_in;
    var ip = ip_in;
    var length = length_in;
    const oend = op + length;
    if (length < 8) {
        while (op < oend) : ({
            op += 1;
            ip += 1;
        }) out[op] = out[ip];
        return;
    }
    overlapCopy8(out, &op, &ip, op - ip);
    length -= 8;
    if (sle(oend, oend_w)) {
        wildcopyOverlap(out, op, ip, length);
        return;
    }
    if (sle(op, oend_w)) {
        const w: usize = @intCast(oend_w);
        wildcopyOverlap(out, op, ip, w - op);
        ip += w - op;
        op = w;
    }
    while (op < oend) : ({
        op += 1;
        ip += 1;
    }) out[op] = out[ip];
}

/// `ZSTD_safecopy` from a separate buffer (literals).
fn safecopyNoOverlap(out: []u8, op_in: usize, oend_w: isize, src: []const u8, ip_in: usize, length: usize) void {
    var op = op_in;
    var ip = ip_in;
    const oend = op + length;
    if (length < 8) {
        while (op < oend) : ({
            op += 1;
            ip += 1;
        }) out[op] = src[ip];
        return;
    }
    if (sle(oend, oend_w)) {
        wildcopyNoOverlap(out, op, src, ip, length);
        return;
    }
    if (sle(op, oend_w)) {
        const w: usize = @intCast(oend_w);
        wildcopyNoOverlap(out, op, src, ip, w - op);
        ip += w - op;
        op = w;
    }
    while (op < oend) : ({
        op += 1;
        ip += 1;
    }) out[op] = src[ip];
}

/// Copies the part of a match that lies in the external segment; returns
/// true when the whole match was there.
inline fn copyFromExt(h: *const History, o_lit_end: usize, seq: *Seq, op: *usize) Error!bool {
    const back = seq.offset - (o_lit_end - h.prefix); // bytes before prefix
    if (back > h.ext.len) return error.CorruptionDetected;
    const m = h.ext.len - back;
    if (m + seq.match_length <= h.ext.len) {
        @memcpy(h.out[o_lit_end..][0..seq.match_length], h.ext[m..][0..seq.match_length]);
        return true;
    }
    const length1 = h.ext.len - m;
    @memcpy(h.out[o_lit_end..][0..length1], h.ext[m..][0..length1]);
    op.* = o_lit_end + length1;
    seq.match_length -= length1;
    return false;
}

/// `ZSTD_execSequenceEnd`: the careful path near the end of the output
/// or of the literals.
fn execSequenceEnd(h: *const History, op_in: usize, oend: usize, seq_in: Seq, st: *State) Error!usize {
    var seq = seq_in;
    var op = op_in;
    const o_lit_end = op + seq.lit_length;
    const sequence_length = seq.lit_length + seq.match_length;
    // may lie before the start of the buffer, as the pointer does in C
    const oend_w: isize = @as(isize, @intCast(oend)) - wildcopy_overlength;

    if (sequence_length > oend - op) return error.DstSizeTooSmall;
    if (seq.lit_length > st.lit_end - st.lit_pos) return error.CorruptionDetected;

    safecopyNoOverlap(h.out, op, oend_w, st.lit_src, st.lit_pos, seq.lit_length);
    op = o_lit_end;
    st.lit_pos += seq.lit_length;

    var match: usize = undefined;
    if (seq.offset > o_lit_end - h.prefix) {
        if (try copyFromExt(h, o_lit_end, &seq, &op)) return sequence_length;
        match = h.prefix;
    } else {
        match = o_lit_end - seq.offset;
    }
    safecopyOverlap(h.out, op, oend_w, match, seq.match_length);
    return sequence_length;
}

/// `ZSTD_execSequence`.
inline fn execSequence(h: *const History, op_in: usize, oend: usize, seq_in: Seq, st: *State) Error!usize {
    var seq = seq_in;
    var op = op_in;
    const o_lit_end = op + seq.lit_length;
    const sequence_length = seq.lit_length + seq.match_length;
    const o_match_end = op + sequence_length;
    const i_lit_end = st.lit_pos + seq.lit_length;

    if (i_lit_end > st.lit_end or oend < wildcopy_overlength or o_match_end > oend - wildcopy_overlength)
        return execSequenceEnd(h, op, oend, seq, st);

    // copy literals: 16 bytes at once, the rest wildly
    copy16(h.out, op, st.lit_src, st.lit_pos);
    if (seq.lit_length > 16) wildcopyNoOverlap(h.out, op + 16, st.lit_src, st.lit_pos + 16, seq.lit_length - 16);
    op = o_lit_end;
    st.lit_pos = i_lit_end;

    var match: usize = undefined;
    if (seq.offset > o_lit_end - h.prefix) {
        if (try copyFromExt(h, o_lit_end, &seq, &op)) return sequence_length;
        match = h.prefix;
    } else {
        match = o_lit_end - seq.offset;
    }

    if (seq.offset >= wildcopy_veclen) {
        wildcopyNoOverlap(h.out, op, h.out, match, seq.match_length);
        return sequence_length;
    }
    // close-range match, overlap
    overlapCopy8(h.out, &op, &match, seq.offset);
    if (seq.match_length > 8) wildcopyOverlap(h.out, op, match, seq.match_length - 8);
    return sequence_length;
}

/// `ZSTD_decompressSequences_body`. Writes at `h.out[op0..op0 + capacity]`.
fn decompressSequences(st: *State, h: *const History, op0: usize, capacity: usize, src: []const u8, nb_seq_in: u32) Error!usize {
    var op = op0;
    const oend = op0 + capacity;
    var nb_seq = nb_seq_in;

    if (nb_seq != 0) {
        st.fse_entropy = true;
        var ss: SeqState = undefined;
        for (0..3) |i| ss.prev[i] = st.rep[i];
        ss.d = DStream.init(src) catch return error.CorruptionDetected;
        ss.ll = FseState.init(&ss.d, st.ll_ptr);
        ss.of = FseState.init(&ss.d, st.of_ptr);
        ss.ml = FseState.init(&ss.d, st.ml_ptr);

        while (nb_seq != 0) : (nb_seq -= 1) {
            const seq = decodeSequence(&ss, nb_seq == 1);
            op += try execSequence(h, op, oend, seq, st);
        }

        // check if reached exact end
        if (!ss.d.endOfStream()) return error.CorruptionDetected;
        for (0..3) |i| st.rep[i] = @truncate(ss.prev[i]);
    }

    // last literal segment
    const last_ll = st.lit_end - st.lit_pos;
    if (last_ll > oend - op) return error.DstSizeTooSmall;
    @memcpy(h.out[op..][0..last_ll], st.lit_src[st.lit_pos..][0..last_ll]);
    op += last_ll;
    return op - op0;
}

/// `ZSTD_decompressBlock_internal`: decodes one compressed block into
/// `h.out[op..op + capacity]`. Returns the decoded size.
pub fn decompressBlock(st: *State, h: *const History, op: usize, capacity: usize, src: []const u8) Error!usize {
    if (src.len > st.block_size_max) return error.SrcSizeWrong;
    const lit_c_size = try decodeLiterals(st, src, capacity);
    const rest = src[lit_c_size..];
    var nb_seq: u32 = undefined;
    const seq_h_size = try decodeSeqHeaders(st, &nb_seq, rest);
    if (capacity == 0 and nb_seq > 0) return error.DstSizeTooSmall;
    return decompressSequences(st, h, op, capacity, rest[seq_h_size..], nb_seq);
}

test "default sequence tables match libzstd's literal tables" {
    // spot checks against LL/OF/ML_defaultDTable in zstd_decompress_block.c
    try std.testing.expectEqual(@as(u32, 6), ll_default.table_log);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 0, .nb_additional_bits = 0, .nb_bits = 4, .base_value = 0 }, ll_default.cells[0]);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 32, .nb_additional_bits = 6, .nb_bits = 5, .base_value = 64 }, ll_default.cells[17]);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 0, .nb_additional_bits = 13, .nb_bits = 6, .base_value = 8192 }, ll_default.cells[63]);
    try std.testing.expectEqual(@as(u32, 5), of_default.table_log);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 0, .nb_additional_bits = 6, .nb_bits = 4, .base_value = 61 }, of_default.cells[1]);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 0, .nb_additional_bits = 24, .nb_bits = 5, .base_value = 16777213 }, of_default.cells[31]);
    try std.testing.expectEqual(@as(u32, 6), ml_default.table_log);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 0, .nb_additional_bits = 0, .nb_bits = 6, .base_value = 3 }, ml_default.cells[0]);
    try std.testing.expectEqual(SeqSymbol{ .next_state = 0, .nb_additional_bits = 10, .nb_bits = 6, .base_value = 1027 }, ml_default.cells[63]);
}
