// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Huffman decoder: table header (`HUF_readStats`), single-symbol (X1) and
//! double-symbol (X2) decoding tables, one- and four-stream decoding.
//!
//! Port of lib/decompress/huf_decompress.c and `HUF_readStats` from
//! lib/common/entropy_common.c (v1.5.7). Four-stream decoding goes through
//! libzstd's "fast" loop whenever it applies (table log 11, every stream at
//! least 8 bytes) and falls back to the checked loop otherwise, as libzstd
//! does on every 64-bit little-endian target except an x86 CPU without
//! BMI2. That choice is visible on corrupt input: the fast path never checks
//! that a stream ended exactly on its end mark, the checked loop does — so
//! it decides which damaged blocks are refused, and it is kept.

const std = @import("std");
const builtin = @import("builtin");
const dbits = @import("dbits.zig");
const DStream = dbits.DStream;
const readLE16 = dbits.readLE16;
const readLE64 = dbits.readLE64;
const highbit32 = dbits.highbit32;

pub const Error = dbits.Error;

pub const tablelog_max = 12;
pub const symbol_value_max = 255;
/// `HUF_DECODER_FAST_TABLELOG`: the fast loops index with 11 bits.
const fast_tablelog = 11;

/// `HUF_DTable` with `ZSTD_HUFFDTABLE_CAPACITY_LOG` = 12: the descriptor
/// fields and room for 4096 cells of either kind (X1 cells are 2 bytes,
/// X2 cells 4).
pub const DTable = struct {
    max_table_log: u8 = tablelog_max,
    /// 0 = X1, 1 = X2.
    table_type: u8 = 0,
    table_log: u8 = tablelog_max,
    cells: [1 << tablelog_max]u32 align(8) = undefined,

    /// X1 cell: low byte = bits consumed, high byte = symbol.
    inline fn x1(dt: *DTable) *[2 << tablelog_max]u16 {
        return @ptrCast(&dt.cells);
    }
    inline fn x1c(dt: *const DTable) *const [2 << tablelog_max]u16 {
        return @ptrCast(&dt.cells);
    }
};

/// X2 cell (`HUF_DEltX2`) as one little-endian word: bits 0..15 the one or
/// two decoded bytes, 16..23 bits consumed, 24..31 how many bytes (1 or 2).
inline fn x2Seq(c: u32) u16 {
    return @truncate(c);
}
inline fn x2NbBits(c: u32) u32 {
    return (c >> 16) & 0xFF;
}
inline fn x2Length(c: u32) u32 {
    return c >> 24;
}

/// `HUF_readStats`: reads the table header into `weights` (the implied
/// last weight included). Returns the header size.
pub fn readStats(weights: *[symbol_value_max + 1]u8, rank_stats: *[tablelog_max + 1]u32, nb_symbols: *u32, table_log_out: *u32, src: []const u8) Error!usize {
    if (src.len == 0) return error.SrcSizeWrong;
    var i_size: usize = src[0];
    var o_size: usize = undefined;
    const hw_size = symbol_value_max + 1;
    if (i_size >= 128) {
        // direct representation, 4 bits per weight
        o_size = i_size - 127;
        i_size = (o_size + 1) / 2;
        if (i_size + 1 > src.len) return error.SrcSizeWrong;
        if (o_size >= hw_size) return error.CorruptionDetected;
        var n: usize = 0;
        while (n < o_size) : (n += 2) {
            weights[n] = src[1 + n / 2] >> 4;
            weights[n + 1] = src[1 + n / 2] & 15;
        }
    } else {
        if (i_size + 1 > src.len) return error.SrcSizeWrong;
        o_size = try dbits.decompressWeights(weights[0 .. hw_size - 1], src[1..][0..i_size], 6);
    }

    @memset(rank_stats, 0);
    var weight_total: u32 = 0;
    for (weights[0..o_size]) |w| {
        if (w > tablelog_max) return error.CorruptionDetected;
        rank_stats[w] += 1;
        weight_total += (@as(u32, 1) << @intCast(w)) >> 1;
    }
    if (weight_total == 0) return error.CorruptionDetected;

    const table_log = highbit32(weight_total) + 1;
    if (table_log > tablelog_max) return error.CorruptionDetected;
    table_log_out.* = table_log;
    {
        const total: u32 = @as(u32, 1) << @intCast(table_log);
        const rest = total - weight_total;
        const verif: u32 = @as(u32, 1) << @intCast(highbit32(rest));
        const last_weight = highbit32(rest) + 1;
        if (verif != rest) return error.CorruptionDetected;
        weights[o_size] = @intCast(last_weight);
        rank_stats[last_weight] += 1;
    }
    if (rank_stats[1] < 2 or (rank_stats[1] & 1) != 0) return error.CorruptionDetected;
    nb_symbols.* = @intCast(o_size + 1);
    return i_size + 1;
}

// ---------------------------------------------------------------- X1

/// `HUF_readDTableX1_wksp`.
pub fn readDTableX1(dt: *DTable, src: []const u8) Error!usize {
    var weights: [symbol_value_max + 1]u8 = undefined;
    var rank_val: [tablelog_max + 1]u32 = undefined;
    var nb_symbols: u32 = 0;
    var table_log: u32 = 0;
    const i_size = try readStats(&weights, &rank_val, &nb_symbols, &table_log, src);

    {
        const max_table_log: u32 = @as(u32, dt.max_table_log) + 1;
        const target: u32 = @min(max_table_log, fast_tablelog);
        // HUF_rescaleStats
        if (table_log < target) {
            const scale = target - table_log;
            for (weights[0..nb_symbols]) |*w| {
                if (w.* != 0) w.* += @intCast(scale);
            }
            var s: u32 = target;
            while (s > scale) : (s -= 1) rank_val[s] = rank_val[s - scale];
            s = scale;
            while (s > 0) : (s -= 1) rank_val[s] = 0;
            table_log = target;
        }
        if (table_log > max_table_log) return error.TableLogTooLarge;
        dt.table_type = 0;
        dt.table_log = @intCast(table_log);
    }

    var rank_start: [tablelog_max + 1]u32 = undefined;
    var symbols: [symbol_value_max + 1]u8 = undefined;
    {
        var next: u32 = 0;
        var n: u32 = 0;
        while (n < table_log + 1) : (n += 1) {
            rank_start[n] = next;
            next += rank_val[n];
        }
        n = 0;
        while (n < nb_symbols) : (n += 1) {
            const w = weights[n];
            symbols[rank_start[w]] = @intCast(n);
            rank_start[w] += 1;
        }
    }

    const cells = dt.x1();
    var symbol: u32 = rank_val[0];
    var start: u32 = 0;
    var w: u32 = 1;
    while (w < table_log + 1) : (w += 1) {
        const symbol_count = rank_val[w];
        const length: u32 = (@as(u32, 1) << @intCast(w)) >> 1;
        const nb_bits: u16 = @intCast(table_log + 1 - w);
        var s: u32 = 0;
        while (s < symbol_count) : (s += 1) {
            const cell: u16 = (@as(u16, symbols[symbol + s]) << 8) | nb_bits;
            @memset(cells[start..][0..length], cell);
            start += length;
        }
        symbol += symbol_count;
    }
    return i_size;
}

inline fn decodeSymbolX1(d: *DStream, cells: *const [2 << tablelog_max]u16, dt_log: u32) u8 {
    const val: usize = @intCast(d.lookBitsFast(dt_log));
    const c = cells[val];
    d.skipBits(c & 0xFF);
    return @truncate(c >> 8);
}

/// `HUF_decodeStreamX1`: fills `dst[p..p_end]`.
fn decodeStreamX1(dst: []u8, p_in: usize, p_end: usize, d: *DStream, cells: *const [2 << tablelog_max]u16, dt_log: u32) void {
    var p = p_in;
    if (p_end - p > 3) {
        while (@intFromBool(d.reload() == .unfinished) & @intFromBool(p + 3 < p_end) != 0) {
            dst[p + 0] = decodeSymbolX1(d, cells, dt_log);
            dst[p + 1] = decodeSymbolX1(d, cells, dt_log);
            dst[p + 2] = decodeSymbolX1(d, cells, dt_log);
            dst[p + 3] = decodeSymbolX1(d, cells, dt_log);
            p += 4;
        }
    } else {
        _ = d.reload();
    }
    while (p < p_end) : (p += 1) dst[p] = decodeSymbolX1(d, cells, dt_log);
}

/// `HUF_decompress1X1_usingDTable_internal`.
fn decompress1X1(dst: []u8, src: []const u8, dt: *const DTable) Error!void {
    var d = try DStream.init(src);
    decodeStreamX1(dst, 0, dst.len, &d, dt.x1c(), dt.table_log);
    if (!d.endOfStream()) return error.CorruptionDetected;
}

/// The checked four-stream loop (`HUF_decompress4X1_usingDTable_internal_body`).
fn decompress4X1Body(dst: []u8, src: []const u8, dt: *const DTable) Error!void {
    if (src.len < 10) return error.CorruptionDetected;
    if (dst.len < 6) return error.CorruptionDetected;
    const cells = dt.x1c();
    const dt_log: u32 = dt.table_log;
    const oend = dst.len;
    const olimit = oend - 3;
    const l1: usize = readLE16(src, 0);
    const l2: usize = readLE16(src, 2);
    const l3: usize = readLE16(src, 4);
    const l4 = src.len -% (l1 + l2 + l3 + 6);
    if (l4 > src.len) return error.CorruptionDetected;
    const is1: usize = 6;
    const is2 = is1 + l1;
    const is3 = is2 + l2;
    const is4 = is3 + l3;
    const seg = (dst.len + 3) / 4;
    const os2 = seg;
    const os3 = os2 + seg;
    const os4 = os3 + seg;
    if (os4 > oend) return error.CorruptionDetected;
    var d1 = try DStream.init(src[is1..][0..l1]);
    var d2 = try DStream.init(src[is2..][0..l2]);
    var d3 = try DStream.init(src[is3..][0..l3]);
    var d4 = try DStream.init(src[is4..][0..l4]);
    var op1: usize = 0;
    var op2 = os2;
    var op3 = os3;
    var op4 = os4;
    var end_signal = true;
    if (oend - op4 >= 8) {
        while (end_signal and op4 < olimit) {
            inline for (0..4) |_| {
                dst[op1] = decodeSymbolX1(&d1, cells, dt_log);
                dst[op2] = decodeSymbolX1(&d2, cells, dt_log);
                dst[op3] = decodeSymbolX1(&d3, cells, dt_log);
                dst[op4] = decodeSymbolX1(&d4, cells, dt_log);
                op1 += 1;
                op2 += 1;
                op3 += 1;
                op4 += 1;
            }
            const r1 = d1.reloadFast() == .unfinished;
            const r2 = d2.reloadFast() == .unfinished;
            const r3 = d3.reloadFast() == .unfinished;
            const r4 = d4.reloadFast() == .unfinished;
            end_signal = r1 and r2 and r3 and r4;
        }
    }
    if (op1 > os2) return error.CorruptionDetected;
    if (op2 > os3) return error.CorruptionDetected;
    if (op3 > os4) return error.CorruptionDetected;
    decodeStreamX1(dst, op1, os2, &d1, cells, dt_log);
    decodeStreamX1(dst, op2, os3, &d2, cells, dt_log);
    decodeStreamX1(dst, op3, os4, &d3, cells, dt_log);
    decodeStreamX1(dst, op4, oend, &d4, cells, dt_log);
    if (!(d1.endOfStream() and d2.endOfStream() and d3.endOfStream() and d4.endOfStream()))
        return error.CorruptionDetected;
}

/// `HUF_DecompressFastArgs`: positions are indices (`ip` into `src`,
/// `op` into `dst`); `iend[s]` is where stream `s` begins.
const FastArgs = struct {
    ip: [4]usize,
    op: [4]usize,
    bits: [4]u64,
    iend: [4]usize,
};

fn initFastDStream(src: []const u8, ip: usize) u64 {
    const last = src[ip + 7];
    const consumed: u6 = if (last != 0) @intCast(8 - highbit32(last)) else 0;
    const value = readLE64(src, ip) | 1;
    return value << consumed;
}

/// `HUF_DecompressFastArgs_init`: null when the fast loop does not apply.
fn fastArgsInit(dst: []u8, src: []const u8, dt_log: u32) Error!?FastArgs {
    if (comptime builtin.cpu.arch.endian() != .little or @sizeOf(usize) != 8) return null;
    if (dst.len == 0) return null;
    if (src.len < 10) return error.CorruptionDetected;
    if (dt_log != fast_tablelog) return null;
    var a: FastArgs = undefined;
    const l1: usize = readLE16(src, 0);
    const l2: usize = readLE16(src, 2);
    const l3: usize = readLE16(src, 4);
    const l4 = src.len -% (l1 + l2 + l3 + 6);
    a.iend[0] = 6;
    a.iend[1] = a.iend[0] + l1;
    a.iend[2] = a.iend[1] + l2;
    a.iend[3] = a.iend[2] + l3;
    if (l1 < 8 or l2 < 8 or l3 < 8 or l4 < 8) return null;
    if (l4 > src.len) return error.CorruptionDetected;
    a.ip[0] = a.iend[1] - 8;
    a.ip[1] = a.iend[2] - 8;
    a.ip[2] = a.iend[3] - 8;
    a.ip[3] = src.len - 8;
    const seg = (dst.len + 3) / 4;
    a.op[0] = 0;
    a.op[1] = seg;
    a.op[2] = 2 * seg;
    a.op[3] = 3 * seg;
    if (a.op[3] >= dst.len) return null;
    for (0..4) |s| a.bits[s] = initFastDStream(src, a.ip[s]);
    return a;
}

/// `HUF_initRemainingDStream`: a checked reader over what the fast loop
/// left of stream `s`, floored at the start of all four streams.
fn initRemaining(src: []const u8, a: *const FastArgs, s: usize, segment_end: usize) Error!DStream {
    if (a.op[s] > segment_end) return error.CorruptionDetected;
    if (a.ip[s] +% 8 < a.iend[s]) return error.CorruptionDetected;
    return .{
        .container = readLE64(src, a.ip[s]),
        .bits_consumed = @ctz(a.bits[s]),
        .buf = src,
        .ptr = a.ip[s],
        .start = 0,
    };
}

/// `HUF_decompress4X1_usingDTable_internal_fast_c_loop`.
fn fastLoopX1(dst: []u8, src: []const u8, cells: *const [2 << tablelog_max]u16, a: *FastArgs) void {
    var bits = a.bits;
    var ip = a.ip;
    var op = a.op;
    const oend = dst.len;
    outer: while (true) {
        const oiters = (oend - op[3]) / 5;
        const iiters = ip[0] / 7;
        const iters = @min(oiters, iiters);
        const olimit = op[3] + iters * 5;
        if (op[3] == olimit) break;
        for (1..4) |s| {
            if (ip[s] < ip[s - 1]) break :outer;
        }
        while (true) {
            inline for (0..5) |k| {
                inline for (0..4) |s| {
                    const index: usize = @intCast(bits[s] >> 53);
                    const entry = cells[index];
                    bits[s] <<= @intCast(entry & 0x3F);
                    dst[op[s] + k] = @truncate(entry >> 8);
                }
            }
            inline for (0..4) |s| {
                const ctz: u32 = @ctz(bits[s]);
                const nb_bits: u6 = @intCast(ctz & 7);
                const nb_bytes = ctz >> 3;
                op[s] += 5;
                ip[s] -= nb_bytes;
                bits[s] = readLE64(src, ip[s]) | 1;
                bits[s] <<= nb_bits;
            }
            if (!(op[3] < olimit)) break;
        }
    }
    a.bits = bits;
    a.ip = ip;
    a.op = op;
}

/// `HUF_decompress4X1_usingDTable_internal_fast`; false = not applicable.
fn decompress4X1Fast(dst: []u8, src: []const u8, dt: *const DTable) Error!bool {
    var a = (try fastArgsInit(dst, src, dt.table_log)) orelse return false;
    const cells = dt.x1c();
    fastLoopX1(dst, src, cells, &a);
    const seg = (dst.len + 3) / 4;
    var segment_end: usize = 0;
    for (0..4) |s| {
        if (seg <= dst.len - segment_end) segment_end += seg else segment_end = dst.len;
        var bit = try initRemaining(src, &a, s, segment_end);
        decodeStreamX1(dst, a.op[s], segment_end, &bit, cells, fast_tablelog);
    }
    return true;
}

fn decompress4X1(dst: []u8, src: []const u8, dt: *const DTable) Error!void {
    if (try decompress4X1Fast(dst, src, dt)) return;
    return decompress4X1Body(dst, src, dt);
}

// ---------------------------------------------------------------- X2

/// `HUF_buildDEltX2U32` (little-endian layout).
inline fn buildDElt(symbol: u32, nb_bits: u32, base_seq: u32, comptime level: u32) u32 {
    const seq = if (level == 1) symbol else base_seq + (symbol << 8);
    return seq + (nb_bits << 16) + (level << 24);
}

/// `HUF_fillDTableX2ForWeight`.
fn fillForWeight(cells: []u32, sorted: []const u8, nb_bits: u32, table_log: u32, base_seq: u32, comptime level: u32) void {
    const length: usize = @as(usize, 1) << @intCast((table_log - nb_bits) & 0x1F);
    var at: usize = 0;
    for (sorted) |sym| {
        @memset(cells[at..][0..length], buildDElt(sym, nb_bits, base_seq, level));
        at += length;
    }
}

const RankValCol = [tablelog_max + 1]u32;

/// `HUF_fillDTableX2Level2`.
fn fillLevel2(cells: []u32, target_log: u32, consumed_bits: u32, rank_val: *const RankValCol, min_weight: u32, max_weight1: u32, sorted: []const u8, rank_start0: []const u32, nb_bits_baseline: u32, base_seq: u32) void {
    if (min_weight > 1) {
        const length: usize = @as(usize, 1) << @intCast((target_log - consumed_bits) & 0x1F);
        const delt = buildDElt(base_seq, consumed_bits, 0, 1);
        const skip: usize = rank_val[min_weight];
        // libzstd fills in whole 8-byte (2-cell) chunks: 2, 4, or rounded up to 8
        const n: usize = switch (length) {
            2 => 2,
            4 => 4,
            else => (skip + 7) / 8 * 8,
        };
        @memset(cells[0..n], delt);
    }
    var w = min_weight;
    while (w < max_weight1) : (w += 1) {
        const begin = rank_start0[w];
        const end = rank_start0[w + 1];
        const nb_bits = nb_bits_baseline - w;
        const total_bits = nb_bits + consumed_bits;
        fillForWeight(cells[rank_val[w]..], sorted[begin..end], total_bits, target_log, base_seq, 2);
    }
}

/// `HUF_readDTableX2_wksp`.
pub fn readDTableX2(dt: *DTable, src: []const u8) Error!usize {
    var max_table_log: u32 = dt.max_table_log;
    var rank_val: [tablelog_max]RankValCol = undefined;
    var rank_stats = [_]u32{0} ** (tablelog_max + 1);
    var rank_start0 = [_]u32{0} ** (tablelog_max + 3);
    var sorted: [symbol_value_max + 1]u8 = undefined;
    var weights: [symbol_value_max + 1]u8 = undefined;
    var table_log: u32 = undefined;
    var nb_symbols: u32 = undefined;

    if (max_table_log > tablelog_max) return error.TableLogTooLarge;
    const i_size = try readStats(&weights, &rank_stats, &nb_symbols, &table_log, src);
    if (table_log > max_table_log) return error.TableLogTooLarge;
    if (table_log <= fast_tablelog and max_table_log > fast_tablelog) max_table_log = fast_tablelog;

    var max_w = table_log;
    while (rank_stats[max_w] == 0) max_w -= 1;

    // rank_start = rank_start0 + 1
    {
        var next: u32 = 0;
        var w: u32 = 1;
        while (w < max_w + 1) : (w += 1) {
            rank_start0[1 + w] = next;
            next += rank_stats[w];
        }
        rank_start0[1 + 0] = next;
        rank_start0[1 + max_w + 1] = next;
    }
    {
        var s: u32 = 0;
        while (s < nb_symbols) : (s += 1) {
            const w = weights[s];
            const r = rank_start0[1 + w];
            rank_start0[1 + w] += 1;
            sorted[r] = @intCast(s);
        }
        rank_start0[1 + 0] = 0;
    }

    {
        const rank_val0 = &rank_val[0];
        const rescale: i32 = @as(i32, @intCast(max_table_log - table_log)) - 1;
        var next: u32 = 0;
        var w: u32 = 1;
        while (w < max_w + 1) : (w += 1) {
            rank_val0[w] = next;
            next += rank_stats[w] << @intCast(@as(i32, @intCast(w)) + rescale);
        }
        const min_bits = table_log + 1 - max_w;
        var consumed = min_bits;
        while (consumed < max_table_log - min_bits + 1) : (consumed += 1) {
            w = 1;
            while (w < max_w + 1) : (w += 1) rank_val[consumed][w] = rank_val0[w] >> @intCast(consumed);
        }
    }

    // HUF_fillDTableX2
    {
        const cells: []u32 = &dt.cells;
        const target_log = max_table_log;
        const nb_bits_baseline = table_log + 1;
        const rv0 = &rank_val[0];
        const scale_log: i32 = @as(i32, @intCast(nb_bits_baseline)) - @as(i32, @intCast(target_log));
        const min_bits = nb_bits_baseline - max_w;
        const w_end = max_w + 1;
        var w: u32 = 1;
        while (w < w_end) : (w += 1) {
            const begin = rank_start0[w];
            const end = rank_start0[w + 1];
            const nb_bits = nb_bits_baseline - w;
            if (target_log - nb_bits >= min_bits) {
                // enough room for a second symbol
                var start: usize = rv0[w];
                const length: usize = @as(usize, 1) << @intCast((target_log - nb_bits) & 0x1F);
                var min_weight: i32 = @as(i32, @intCast(nb_bits)) + scale_log;
                if (min_weight < 1) min_weight = 1;
                var s = begin;
                while (s != end) : (s += 1) {
                    fillLevel2(cells[start..], target_log, nb_bits, &rank_val[nb_bits], @intCast(min_weight), w_end, &sorted, &rank_start0, nb_bits_baseline, sorted[s]);
                    start += length;
                }
            } else {
                fillForWeight(cells[rv0[w]..], sorted[begin..end], nb_bits, target_log, 0, 1);
            }
        }
    }

    dt.table_log = @intCast(max_table_log);
    dt.table_type = 1;
    return i_size;
}

inline fn decodeSymbolX2(dst: []u8, p: usize, d: *DStream, cells: *const [1 << tablelog_max]u32, dt_log: u32) usize {
    const val: usize = @intCast(d.lookBitsFast(dt_log));
    const c = cells[val];
    std.mem.writeInt(u16, dst[p..][0..2], x2Seq(c), .little);
    d.skipBits(x2NbBits(c));
    return x2Length(c);
}

inline fn decodeLastSymbolX2(dst: []u8, p: usize, d: *DStream, cells: *const [1 << tablelog_max]u32, dt_log: u32) usize {
    const val: usize = @intCast(d.lookBitsFast(dt_log));
    const c = cells[val];
    dst[p] = @truncate(x2Seq(c));
    if (x2Length(c) == 1) {
        d.skipBits(x2NbBits(c));
    } else if (d.bits_consumed < 64) {
        d.skipBits(x2NbBits(c));
        if (d.bits_consumed > 64) d.bits_consumed = 64; // ugly, but necessary
    }
    return 1;
}

/// `HUF_decodeStreamX2`. Returns how far it got past `p_in`.
fn decodeStreamX2(dst: []u8, p_in: usize, p_end: usize, d: *DStream, cells: *const [1 << tablelog_max]u32, dt_log: u32) usize {
    var p = p_in;
    if (p_end - p >= 8) {
        if (dt_log <= 11) {
            while (@intFromBool(d.reload() == .unfinished) & @intFromBool(p + 9 < p_end) != 0) {
                inline for (0..5) |_| p += decodeSymbolX2(dst, p, d, cells, dt_log);
            }
        } else {
            while (@intFromBool(d.reload() == .unfinished) & @intFromBool(p + 7 < p_end) != 0) {
                inline for (0..4) |_| p += decodeSymbolX2(dst, p, d, cells, dt_log);
            }
        }
    } else {
        _ = d.reload();
    }
    if (p_end - p >= 2) {
        while (@intFromBool(d.reload() == .unfinished) & @intFromBool(p + 2 <= p_end) != 0)
            p += decodeSymbolX2(dst, p, d, cells, dt_log);
        while (p + 2 <= p_end) p += decodeSymbolX2(dst, p, d, cells, dt_log);
    }
    if (p < p_end) p += decodeLastSymbolX2(dst, p, d, cells, dt_log);
    return p - p_in;
}

fn decompress1X2(dst: []u8, src: []const u8, dt: *const DTable) Error!void {
    var d = try DStream.init(src);
    _ = decodeStreamX2(dst, 0, dst.len, &d, &dt.cells, dt.table_log);
    if (!d.endOfStream()) return error.CorruptionDetected;
}

fn decompress4X2Body(dst: []u8, src: []const u8, dt: *const DTable) Error!void {
    if (src.len < 10) return error.CorruptionDetected;
    if (dst.len < 6) return error.CorruptionDetected;
    const cells = &dt.cells;
    const dt_log: u32 = dt.table_log;
    const oend = dst.len;
    const olimit = oend -% 7;
    const l1: usize = readLE16(src, 0);
    const l2: usize = readLE16(src, 2);
    const l3: usize = readLE16(src, 4);
    const l4 = src.len -% (l1 + l2 + l3 + 6);
    if (l4 > src.len) return error.CorruptionDetected;
    const is1: usize = 6;
    const is2 = is1 + l1;
    const is3 = is2 + l2;
    const is4 = is3 + l3;
    const seg = (dst.len + 3) / 4;
    const os2 = seg;
    const os3 = os2 + seg;
    const os4 = os3 + seg;
    if (os4 > oend) return error.CorruptionDetected;
    var d1 = try DStream.init(src[is1..][0..l1]);
    var d2 = try DStream.init(src[is2..][0..l2]);
    var d3 = try DStream.init(src[is3..][0..l3]);
    var d4 = try DStream.init(src[is4..][0..l4]);
    var op1: usize = 0;
    var op2 = os2;
    var op3 = os3;
    var op4 = os4;
    var end_signal = true;
    if (oend - op4 >= 8) {
        while (end_signal and op4 < olimit) {
            inline for (0..4) |_| {
                op1 += decodeSymbolX2(dst, op1, &d1, cells, dt_log);
                op2 += decodeSymbolX2(dst, op2, &d2, cells, dt_log);
                op3 += decodeSymbolX2(dst, op3, &d3, cells, dt_log);
                op4 += decodeSymbolX2(dst, op4, &d4, cells, dt_log);
            }
            const r1 = d1.reloadFast() == .unfinished;
            const r2 = d2.reloadFast() == .unfinished;
            const r3 = d3.reloadFast() == .unfinished;
            const r4 = d4.reloadFast() == .unfinished;
            end_signal = r1 and r2 and r3 and r4;
        }
    }
    if (op1 > os2) return error.CorruptionDetected;
    if (op2 > os3) return error.CorruptionDetected;
    if (op3 > os4) return error.CorruptionDetected;
    _ = decodeStreamX2(dst, op1, os2, &d1, cells, dt_log);
    _ = decodeStreamX2(dst, op2, os3, &d2, cells, dt_log);
    _ = decodeStreamX2(dst, op3, os4, &d3, cells, dt_log);
    _ = decodeStreamX2(dst, op4, oend, &d4, cells, dt_log);
    if (!(d1.endOfStream() and d2.endOfStream() and d3.endOfStream() and d4.endOfStream()))
        return error.CorruptionDetected;
}

/// `HUF_decompress4X2_usingDTable_internal_fast_c_loop`.
fn fastLoopX2(dst: []u8, src: []const u8, cells: *const [1 << tablelog_max]u32, a: *FastArgs) void {
    var bits = a.bits;
    var ip = a.ip;
    var op = a.op;
    const oend = [4]usize{ op[1], op[2], op[3], dst.len };
    outer: while (true) {
        var iters = ip[0] / 7;
        for (0..4) |s| iters = @min(iters, (oend[s] - op[s]) / 10);
        const olimit = op[3] + iters * 5;
        if (op[3] == olimit) break;
        for (1..4) |s| {
            if (ip[s] < ip[s - 1]) break :outer;
        }
        while (true) {
            inline for (0..5) |_| {
                inline for (0..4) |s| {
                    const index: usize = @intCast(bits[s] >> 53);
                    const c = cells[index];
                    std.mem.writeInt(u16, dst[op[s]..][0..2], x2Seq(c), .little);
                    bits[s] <<= @intCast(x2NbBits(c) & 0x3F);
                    op[s] += x2Length(c);
                }
            }
            inline for (0..4) |s| {
                const ctz: u32 = @ctz(bits[s]);
                const nb_bits: u6 = @intCast(ctz & 7);
                const nb_bytes = ctz >> 3;
                ip[s] -= nb_bytes;
                bits[s] = readLE64(src, ip[s]) | 1;
                bits[s] <<= nb_bits;
            }
            if (!(op[3] < olimit)) break;
        }
    }
    a.bits = bits;
    a.ip = ip;
    a.op = op;
}

fn decompress4X2Fast(dst: []u8, src: []const u8, dt: *const DTable) Error!bool {
    var a = (try fastArgsInit(dst, src, dt.table_log)) orelse return false;
    fastLoopX2(dst, src, &dt.cells, &a);
    const seg = (dst.len + 3) / 4;
    var segment_end: usize = 0;
    for (0..4) |s| {
        if (seg <= dst.len - segment_end) segment_end += seg else segment_end = dst.len;
        var bit = try initRemaining(src, &a, s, segment_end);
        a.op[s] += decodeStreamX2(dst, a.op[s], segment_end, &bit, &dt.cells, fast_tablelog);
        if (a.op[s] != segment_end) return error.CorruptionDetected;
    }
    return true;
}

fn decompress4X2(dst: []u8, src: []const u8, dt: *const DTable) Error!void {
    if (try decompress4X2Fast(dst, src, dt)) return;
    return decompress4X2Body(dst, src, dt);
}

// ---------------------------------------------------------------- entry points

const AlgoTime = struct { table_time: u32, decode256_time: u32 };
const algo_time = [16][2]AlgoTime{
    .{ .{ .table_time = 0, .decode256_time = 0 }, .{ .table_time = 1, .decode256_time = 1 } },
    .{ .{ .table_time = 0, .decode256_time = 0 }, .{ .table_time = 1, .decode256_time = 1 } },
    .{ .{ .table_time = 150, .decode256_time = 216 }, .{ .table_time = 381, .decode256_time = 119 } },
    .{ .{ .table_time = 170, .decode256_time = 205 }, .{ .table_time = 514, .decode256_time = 112 } },
    .{ .{ .table_time = 177, .decode256_time = 199 }, .{ .table_time = 539, .decode256_time = 110 } },
    .{ .{ .table_time = 197, .decode256_time = 194 }, .{ .table_time = 644, .decode256_time = 107 } },
    .{ .{ .table_time = 221, .decode256_time = 192 }, .{ .table_time = 735, .decode256_time = 107 } },
    .{ .{ .table_time = 256, .decode256_time = 189 }, .{ .table_time = 881, .decode256_time = 106 } },
    .{ .{ .table_time = 359, .decode256_time = 188 }, .{ .table_time = 1167, .decode256_time = 109 } },
    .{ .{ .table_time = 582, .decode256_time = 187 }, .{ .table_time = 1570, .decode256_time = 114 } },
    .{ .{ .table_time = 688, .decode256_time = 187 }, .{ .table_time = 1712, .decode256_time = 122 } },
    .{ .{ .table_time = 825, .decode256_time = 186 }, .{ .table_time = 1965, .decode256_time = 136 } },
    .{ .{ .table_time = 976, .decode256_time = 185 }, .{ .table_time = 2131, .decode256_time = 150 } },
    .{ .{ .table_time = 1180, .decode256_time = 186 }, .{ .table_time = 2070, .decode256_time = 175 } },
    .{ .{ .table_time = 1377, .decode256_time = 185 }, .{ .table_time = 1731, .decode256_time = 202 } },
    .{ .{ .table_time = 1412, .decode256_time = 185 }, .{ .table_time = 1695, .decode256_time = 202 } },
};

/// `HUF_selectDecoder`: true = X2. Which table libzstd builds decides the
/// repeat-table case (`set_repeat` reuses it), so the choice is kept.
pub fn selectX2(dst_size: usize, c_src_size: usize) bool {
    const q: usize = if (c_src_size >= dst_size) 15 else c_src_size * 16 / dst_size;
    const d256: u32 = @intCast(dst_size >> 8);
    const t0 = algo_time[q][0].table_time + algo_time[q][0].decode256_time * d256;
    var t1 = algo_time[q][1].table_time + algo_time[q][1].decode256_time * d256;
    t1 += t1 >> 5;
    return t1 < t0;
}

/// `HUF_decompress1X1_DCtx_wksp`: new table, one stream (libzstd reads a
/// single-stream table as X1 unless built with HUF_FORCE_DECOMPRESS_X2).
pub fn decompress1X1Table(dt: *DTable, dst: []u8, src: []const u8) Error!void {
    const h = try readDTableX1(dt, src);
    if (h >= src.len) return error.SrcSizeWrong;
    return decompress1X1(dst, src[h..], dt);
}

/// `HUF_decompress4X_hufOnly_wksp`: new table, four streams.
pub fn decompress4XTable(dt: *DTable, dst: []u8, src: []const u8) Error!void {
    if (dst.len == 0) return error.DstSizeTooSmall;
    if (src.len == 0) return error.CorruptionDetected;
    if (selectX2(dst.len, src.len)) {
        const h = try readDTableX2(dt, src);
        if (h >= src.len) return error.SrcSizeWrong;
        return decompress4X2(dst, src[h..], dt);
    }
    const h = try readDTableX1(dt, src);
    if (h >= src.len) return error.SrcSizeWrong;
    return decompress4X1(dst, src[h..], dt);
}

/// `HUF_decompress1X_usingDTable`: the previous table, one stream.
pub fn decompress1XUsing(dt: *const DTable, dst: []u8, src: []const u8) Error!void {
    return if (dt.table_type != 0) decompress1X2(dst, src, dt) else decompress1X1(dst, src, dt);
}

/// `HUF_decompress4X_usingDTable`: the previous table, four streams.
pub fn decompress4XUsing(dt: *const DTable, dst: []u8, src: []const u8) Error!void {
    return if (dt.table_type != 0) decompress4X2(dst, src, dt) else decompress4X1(dst, src, dt);
}
