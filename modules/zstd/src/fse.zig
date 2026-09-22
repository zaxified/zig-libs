// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Finite State Entropy encoder: normalisation, table header, CTable, coding.
//!
//! Port of libzstd lib/compress/fse_compress.c and the encoder half of
//! lib/common/fse.h (v1.5.7). Every rounding decision is kept verbatim: the
//! frame this module emits is compared byte-for-byte against the reference, so
//! "equivalent" normalisation is not good enough.
//!
//! The CTable is a struct rather than libzstd's packed `unsigned[]` blob; only
//! the values stored in it matter to the output.

const std = @import("std");
const CStream = @import("bitstream.zig").CStream;

pub const Error = error{ DstSizeTooSmall, Generic };

pub const min_table_log = 5;
pub const max_table_log = 12;
pub const default_table_log = 11;

/// Largest table log this module builds (sequence tables use 9, Huffman
/// weight tables 6).
const table_log_cap = 9;
/// Largest alphabet this module codes with FSE (match-length codes 0..52).
const symbol_cap = 53;

pub inline fn highbit32(v: u32) u32 {
    std.debug.assert(v != 0);
    return 31 - @as(u32, @clz(v));
}

fn minTableLog(src_size: usize, max_symbol: u32) u32 {
    std.debug.assert(src_size > 1);
    const min_bits_src = highbit32(@truncate(src_size)) + 1;
    const min_bits_symbols = highbit32(max_symbol) + 2;
    return @min(min_bits_src, min_bits_symbols);
}

/// `FSE_optimalTableLog_internal`.
pub fn optimalTableLogInternal(max_table_log_in: u32, src_size: usize, max_symbol: u32, minus: u32) u32 {
    std.debug.assert(src_size > 1);
    // highbit32(srcSize-1) - minus, in U32 arithmetic (may wrap; the clamps below absorb it)
    const max_bits_src = highbit32(@truncate(src_size - 1)) -% minus;
    var table_log = max_table_log_in;
    const min_bits = minTableLog(src_size, max_symbol);
    if (table_log == 0) table_log = default_table_log;
    if (max_bits_src < table_log) table_log = max_bits_src;
    if (min_bits > table_log) table_log = min_bits;
    if (table_log < min_table_log) table_log = min_table_log;
    if (table_log > max_table_log) table_log = max_table_log;
    return table_log;
}

pub fn optimalTableLog(max_table_log_in: u32, src_size: usize, max_symbol: u32) u32 {
    return optimalTableLogInternal(max_table_log_in, src_size, max_symbol, 2);
}

fn normalizeM2(norm: []i16, table_log: u32, counts: []const u32, total_in: usize, max_symbol: u32, low_prob_count: i16) Error!void {
    const not_yet_assigned: i16 = -2;
    var distributed: u32 = 0;
    var total = total_in;
    const low_threshold: u32 = @truncate(total >> @intCast(table_log));
    var low_one: u32 = @truncate((total * 3) >> @intCast(table_log + 1));

    var s: u32 = 0;
    while (s <= max_symbol) : (s += 1) {
        if (counts[s] == 0) {
            norm[s] = 0;
            continue;
        }
        if (counts[s] <= low_threshold) {
            norm[s] = low_prob_count;
            distributed += 1;
            total -= counts[s];
            continue;
        }
        if (counts[s] <= low_one) {
            norm[s] = 1;
            distributed += 1;
            total -= counts[s];
            continue;
        }
        norm[s] = not_yet_assigned;
    }
    var to_distribute: u32 = (@as(u32, 1) << @intCast(table_log)) - distributed;
    if (to_distribute == 0) return;

    if ((total / to_distribute) > low_one) {
        low_one = @truncate((total * 3) / (@as(usize, to_distribute) * 2));
        s = 0;
        while (s <= max_symbol) : (s += 1) {
            if (norm[s] == not_yet_assigned and counts[s] <= low_one) {
                norm[s] = 1;
                distributed += 1;
                total -= counts[s];
            }
        }
        to_distribute = (@as(u32, 1) << @intCast(table_log)) - distributed;
    }

    if (distributed == max_symbol + 1) {
        var max_v: u32 = 0;
        var max_c: u32 = 0;
        s = 0;
        while (s <= max_symbol) : (s += 1) {
            if (counts[s] > max_c) {
                max_v = s;
                max_c = counts[s];
            }
        }
        norm[max_v] += @intCast(to_distribute);
        return;
    }

    if (total == 0) {
        s = 0;
        while (to_distribute > 0) : (s = (s + 1) % (max_symbol + 1)) {
            if (norm[s] > 0) {
                to_distribute -= 1;
                norm[s] += 1;
            }
        }
        return;
    }

    const v_step_log: u6 = @intCast(62 - table_log);
    const mid: u64 = (@as(u64, 1) << (v_step_log - 1)) - 1;
    const r_step: u64 = ((@as(u64, 1) << v_step_log) * to_distribute + mid) / @as(u32, @truncate(total));
    var tmp_total: u64 = mid;
    s = 0;
    while (s <= max_symbol) : (s += 1) {
        if (norm[s] == not_yet_assigned) {
            const end = tmp_total + @as(u64, counts[s]) * r_step;
            const s_start: u32 = @truncate(tmp_total >> v_step_log);
            const s_end: u32 = @truncate(end >> v_step_log);
            const weight = s_end - s_start;
            if (weight < 1) return error.Generic;
            norm[s] = @intCast(weight);
            tmp_total = end;
        }
    }
}

const rtb_table = [_]u32{ 0, 473195, 504333, 520860, 550000, 700000, 750000, 830000 };

/// `FSE_normalizeCount`. Returns the table log used.
pub fn normalizeCount(norm: []i16, table_log_in: u32, counts: []const u32, total: usize, max_symbol: u32, use_low_prob_count: bool) Error!u32 {
    var table_log = table_log_in;
    if (table_log == 0) table_log = default_table_log;
    if (table_log < min_table_log) return error.Generic;
    if (table_log > max_table_log) return error.Generic;
    if (table_log < minTableLog(total, max_symbol)) return error.Generic;

    const low_prob_count: i16 = if (use_low_prob_count) -1 else 1;
    const scale: u6 = @intCast(62 - table_log);
    const step: u64 = (@as(u64, 1) << 62) / @as(u32, @truncate(total));
    const v_step: u64 = @as(u64, 1) << (scale - 20);
    var still_to_distribute: i32 = @as(i32, 1) << @intCast(table_log);
    var largest: u32 = 0;
    var largest_p: i16 = 0;
    const low_threshold: u32 = @truncate(total >> @intCast(table_log));

    var s: u32 = 0;
    while (s <= max_symbol) : (s += 1) {
        if (counts[s] == total) return 0; // RLE special case
        if (counts[s] == 0) {
            norm[s] = 0;
            continue;
        }
        if (counts[s] <= low_threshold) {
            norm[s] = low_prob_count;
            still_to_distribute -= 1;
        } else {
            const cs: u64 = @as(u64, counts[s]) * step;
            var proba: i16 = @intCast(cs >> scale);
            if (proba < 8) {
                const rest_to_beat = v_step * rtb_table[@intCast(proba)];
                proba += @intFromBool(cs - (@as(u64, @intCast(proba)) << scale) > rest_to_beat);
            }
            if (proba > largest_p) {
                largest_p = proba;
                largest = s;
            }
            norm[s] = proba;
            still_to_distribute -= proba;
        }
    }
    if (-still_to_distribute >= (norm[largest] >> 1)) {
        try normalizeM2(norm, table_log, counts, total, max_symbol, low_prob_count);
    } else {
        norm[largest] += @intCast(still_to_distribute);
    }
    return table_log;
}

pub fn nCountWriteBound(max_symbol: u32, table_log: u32) usize {
    const max_header_size = (((max_symbol + 1) * table_log + 4 + 2) / 8) + 1 + 2;
    return if (max_symbol != 0) max_header_size else 512;
}

fn writeNCountGeneric(out_buf: []u8, norm: []const i16, max_symbol: u32, table_log: u32, write_is_safe: bool) Error!usize {
    var out: usize = 0;
    const oend = out_buf.len;
    const table_size: i32 = @as(i32, 1) << @intCast(table_log);
    var bit_stream: u32 = 0;
    var bit_count: u32 = 0;
    var symbol: u32 = 0;
    const alphabet_size = max_symbol + 1;
    var previous_is0 = false;

    bit_stream +%= (table_log - min_table_log) << @intCast(bit_count);
    bit_count += 4;
    var remaining: i32 = table_size + 1;
    var threshold: i32 = table_size;
    var nb_bits: u32 = table_log + 1;

    while (symbol < alphabet_size and remaining > 1) {
        if (previous_is0) {
            var start = symbol;
            while (symbol < alphabet_size and norm[symbol] == 0) symbol += 1;
            if (symbol == alphabet_size) break; // incorrect distribution
            while (symbol >= start + 24) {
                start += 24;
                bit_stream +%= @as(u32, 0xFFFF) << @intCast(bit_count);
                if (!write_is_safe and out + 2 > oend) return error.DstSizeTooSmall;
                out_buf[out] = @truncate(bit_stream);
                out_buf[out + 1] = @truncate(bit_stream >> 8);
                out += 2;
                bit_stream >>= 16;
            }
            while (symbol >= start + 3) {
                start += 3;
                bit_stream +%= @as(u32, 3) << @intCast(bit_count);
                bit_count += 2;
            }
            bit_stream +%= (symbol - start) << @intCast(bit_count);
            bit_count += 2;
            if (bit_count > 16) {
                if (!write_is_safe and out + 2 > oend) return error.DstSizeTooSmall;
                out_buf[out] = @truncate(bit_stream);
                out_buf[out + 1] = @truncate(bit_stream >> 8);
                out += 2;
                bit_stream >>= 16;
                bit_count -= 16;
            }
        }
        {
            var count: i32 = norm[symbol];
            symbol += 1;
            const max: i32 = (2 * threshold - 1) - remaining;
            remaining -= if (count < 0) -count else count;
            count += 1; // +1 for extra accuracy
            if (count >= threshold) count += max;
            bit_stream +%= @as(u32, @bitCast(count)) << @intCast(bit_count);
            bit_count += nb_bits;
            bit_count -= @intFromBool(count < max);
            previous_is0 = (count == 1);
            if (remaining < 1) return error.Generic;
            while (remaining < threshold) {
                nb_bits -= 1;
                threshold >>= 1;
            }
        }
        if (bit_count > 16) {
            if (!write_is_safe and out + 2 > oend) return error.DstSizeTooSmall;
            out_buf[out] = @truncate(bit_stream);
            out_buf[out + 1] = @truncate(bit_stream >> 8);
            out += 2;
            bit_stream >>= 16;
            bit_count -= 16;
        }
    }
    if (remaining != 1) return error.Generic; // incorrect normalized distribution
    std.debug.assert(symbol <= alphabet_size);

    // flush remaining bitStream
    if (!write_is_safe and out + 2 > oend) return error.DstSizeTooSmall;
    out_buf[out] = @truncate(bit_stream);
    out_buf[out + 1] = @truncate(bit_stream >> 8);
    out += (bit_count + 7) / 8;
    return out;
}

/// `FSE_writeNCount`: serialise a normalised distribution as a table header.
pub fn writeNCount(buf: []u8, norm: []const i16, max_symbol: u32, table_log: u32) Error!usize {
    if (table_log > max_table_log) return error.Generic;
    if (table_log < min_table_log) return error.Generic;
    if (buf.len < nCountWriteBound(max_symbol, table_log))
        return writeNCountGeneric(buf, norm, max_symbol, table_log, false);
    return writeNCountGeneric(buf, norm, max_symbol, table_log, true);
}

pub const SymbolTT = struct {
    delta_find_state: i32 = 0,
    delta_nb_bits: u32 = 0,
};

pub const CTable = struct {
    table_log: u32 = 0,
    max_symbol: u32 = 0,
    /// `tableU16`: next state for each (symbol, cumulated slot) pair.
    state_table: [1 << table_log_cap]u16 = undefined,
    symbol_tt: [symbol_cap]SymbolTT = undefined,

    /// `FSE_buildCTable_wksp`.
    pub fn build(ct: *CTable, norm: []const i16, max_symbol: u32, table_log: u32) Error!void {
        if (table_log > table_log_cap or max_symbol >= symbol_cap) return error.Generic;
        const table_size: u32 = @as(u32, 1) << @intCast(table_log);
        const table_mask = table_size - 1;
        const step = (table_size >> 1) + (table_size >> 3) + 3;
        const max_sv1 = max_symbol + 1;
        var cumul: [symbol_cap + 1]u16 = undefined;
        var table_symbol: [1 << table_log_cap]u8 = undefined;
        var high_threshold: u32 = table_size - 1;

        ct.table_log = table_log;
        ct.max_symbol = max_symbol;

        cumul[0] = 0;
        var u: u32 = 1;
        while (u <= max_sv1) : (u += 1) {
            if (norm[u - 1] == -1) { // low proba symbol
                cumul[u] = cumul[u - 1] + 1;
                table_symbol[high_threshold] = @intCast(u - 1);
                high_threshold -%= 1;
            } else {
                std.debug.assert(norm[u - 1] >= 0);
                cumul[u] = cumul[u - 1] + @as(u16, @intCast(norm[u - 1]));
            }
        }
        cumul[max_sv1] = @intCast(table_size + 1);

        if (high_threshold == table_size - 1) {
            // No low-probability symbols: lay each symbol out `norm` times in a
            // row, then scatter the run with the table step. Same assignment as
            // libzstd's 8-byte-at-a-time spread.
            var spread: [1 << table_log_cap]u8 = undefined;
            var pos: usize = 0;
            var s: u32 = 0;
            while (s < max_sv1) : (s += 1) {
                const n: usize = @intCast(norm[s]);
                @memset(spread[pos .. pos + n], @intCast(s));
                pos += n;
            }
            var k: u32 = 0;
            while (k < table_size) : (k += 1) {
                table_symbol[(k *% step) & table_mask] = spread[k];
            }
        } else {
            var position: u32 = 0;
            var symbol: u32 = 0;
            while (symbol < max_sv1) : (symbol += 1) {
                const freq: i32 = norm[symbol];
                var occ: i32 = 0;
                while (occ < freq) : (occ += 1) {
                    table_symbol[position] = @intCast(symbol);
                    position = (position + step) & table_mask;
                    while (position > high_threshold) position = (position + step) & table_mask;
                }
            }
            std.debug.assert(position == 0);
        }

        // Build table
        u = 0;
        while (u < table_size) : (u += 1) {
            const s = table_symbol[u];
            ct.state_table[cumul[s]] = @intCast(table_size + u);
            cumul[s] += 1;
        }

        // Build Symbol Transformation Table
        var total: u32 = 0;
        var s: u32 = 0;
        while (s <= max_symbol) : (s += 1) {
            const n = norm[s];
            switch (n) {
                0 => ct.symbol_tt[s] = .{
                    // For compatibility with FSE_getMaxNbBits()
                    .delta_nb_bits = ((table_log + 1) << 16) - table_size,
                    .delta_find_state = 0,
                },
                -1, 1 => {
                    ct.symbol_tt[s] = .{
                        .delta_nb_bits = (table_log << 16) - table_size,
                        .delta_find_state = @as(i32, @bitCast(total)) - 1,
                    };
                    total += 1;
                },
                else => {
                    const nu: u32 = @intCast(n);
                    const max_bits_out = table_log - highbit32(nu - 1);
                    const min_state_plus = nu << @intCast(max_bits_out);
                    ct.symbol_tt[s] = .{
                        .delta_nb_bits = (max_bits_out << 16) -% min_state_plus,
                        .delta_find_state = @as(i32, @bitCast(total)) - @as(i32, @intCast(nu)),
                    };
                    total += nu;
                },
            }
        }
    }

    /// `FSE_buildCTable_rle`: a table that codes `symbol` in zero bits.
    pub fn buildRle(ct: *CTable, symbol: u8) void {
        ct.table_log = 0;
        ct.max_symbol = symbol;
        ct.state_table[0] = 0;
        ct.state_table[1] = 0;
        ct.symbol_tt[symbol] = .{ .delta_nb_bits = 0, .delta_find_state = 0 };
    }
};

pub const CState = struct {
    value: i64,
    ct: *const CTable,
    state_log: u32,

    /// `FSE_initCState`.
    pub fn init(ct: *const CTable) CState {
        return .{ .value = @as(i64, 1) << @intCast(ct.table_log), .ct = ct, .state_log = ct.table_log };
    }

    /// `FSE_initCState2`: start in the state that encodes `symbol` first for free.
    pub fn init2(ct: *const CTable, symbol: u32) CState {
        var st = init(ct);
        const tt = ct.symbol_tt[symbol];
        const nb_bits_out: u32 = (tt.delta_nb_bits +% (1 << 15)) >> 16;
        const v: u32 = (nb_bits_out << 16) -% tt.delta_nb_bits;
        const idx: i64 = (@as(i64, v) >> @intCast(nb_bits_out)) + tt.delta_find_state;
        st.value = ct.state_table[@intCast(idx)];
        return st;
    }

    /// `FSE_encodeSymbol`.
    pub inline fn encode(st: *CState, bits: *CStream, symbol: u32) void {
        const tt = st.ct.symbol_tt[symbol];
        const nb_bits_out: u32 = @intCast((st.value + tt.delta_nb_bits) >> 16);
        bits.addBits(@bitCast(st.value), nb_bits_out);
        const idx: i64 = (st.value >> @intCast(nb_bits_out)) + tt.delta_find_state;
        st.value = st.ct.state_table[@intCast(idx)];
    }

    /// `FSE_flushCState`.
    pub fn flushState(st: *const CState, bits: *CStream) void {
        bits.addBits(@bitCast(st.value), st.state_log);
        bits.flush();
    }
};

/// `FSE_compress_usingCTable`: code `src` with two interleaved states.
/// Returns the compressed size, or 0 if it did not fit or `src` is too short.
pub fn compressUsingCTable(dst: []u8, src: []const u8, ct: *const CTable) usize {
    if (src.len <= 2) return 0;
    var bits = CStream.init(dst) catch return 0;
    var ip = src.len;
    var s1: CState = undefined;
    var s2: CState = undefined;

    if (src.len & 1 != 0) {
        ip -= 1;
        s1 = CState.init2(ct, src[ip]);
        ip -= 1;
        s2 = CState.init2(ct, src[ip]);
        ip -= 1;
        s1.encode(&bits, src[ip]);
        bits.flush();
    } else {
        ip -= 1;
        s2 = CState.init2(ct, src[ip]);
        ip -= 1;
        s1 = CState.init2(ct, src[ip]);
    }

    // join to multiple of 4 (64-bit accumulator schedule)
    if ((src.len - 2) & 2 != 0) {
        ip -= 1;
        s2.encode(&bits, src[ip]);
        ip -= 1;
        s1.encode(&bits, src[ip]);
        bits.flush();
    }

    while (ip > 0) {
        ip -= 1;
        s2.encode(&bits, src[ip]);
        ip -= 1;
        s1.encode(&bits, src[ip]);
        ip -= 1;
        s2.encode(&bits, src[ip]);
        ip -= 1;
        s1.encode(&bits, src[ip]);
        bits.flush();
    }

    s2.flushState(&bits);
    s1.flushState(&bits);
    return bits.close();
}

test "normalizeCount sums to the table size" {
    const counts = [_]u32{ 100, 50, 25, 12, 6, 3, 2, 1, 1 };
    var norm: [9]i16 = undefined;
    const log = try normalizeCount(&norm, 6, &counts, 200, 8, false);
    try std.testing.expectEqual(@as(u32, 6), log);
    var sum: i32 = 0;
    for (norm) |n| sum += if (n < 0) -n else n;
    try std.testing.expectEqual(@as(i32, 64), sum);
}

test "optimalTableLog clamps to the FSE bounds" {
    try std.testing.expectEqual(@as(u32, 5), optimalTableLog(9, 10, 3));
    try std.testing.expectEqual(@as(u32, 9), optimalTableLog(9, 100000, 35));
}
