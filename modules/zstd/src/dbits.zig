// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Backward bit reader, FSE table headers and the FSE decoder of Huffman
//! weights — the decoder's shared entropy plumbing.
//!
//! Port of libzstd's `BIT_DStream_t` (lib/common/bitstream.h),
//! `FSE_readNCount` (lib/common/entropy_common.c) and
//! lib/common/fse_decompress.c (v1.5.7). The reader keeps libzstd's exact
//! behaviour past the end of a corrupt stream — it goes on handing out bits
//! (from the stale container) and lets the caller's final "stream fully
//! consumed" check reject the block — because what a corrupt stream yields
//! before that check decides which inputs are refused, and this decoder
//! refuses the same ones libzstd does.

const std = @import("std");

pub const Error = error{
    CorruptionDetected,
    SrcSizeWrong,
    TableLogTooLarge,
    MaxSymbolValueTooSmall,
    DstSizeTooSmall,
    Generic,
};

pub inline fn highbit32(v: u32) u32 {
    std.debug.assert(v != 0);
    return 31 - @as(u32, @clz(v));
}

pub inline fn readLE16(b: []const u8, i: usize) u16 {
    return std.mem.readInt(u16, b[i..][0..2], .little);
}
pub inline fn readLE24(b: []const u8, i: usize) u32 {
    return @as(u32, readLE16(b, i)) | (@as(u32, b[i + 2]) << 16);
}
pub inline fn readLE32(b: []const u8, i: usize) u32 {
    return std.mem.readInt(u32, b[i..][0..4], .little);
}
pub inline fn readLE64(b: []const u8, i: usize) u64 {
    return std.mem.readInt(u64, b[i..][0..8], .little);
}

pub const Status = enum(u2) { unfinished = 0, end_of_buffer = 1, completed = 2, overflow = 3 };

/// `BIT_DStream_t` with a 64-bit container. Positions are indices into
/// `buf`; `start` is where the stream begins (not always 0: the Huffman
/// fast path hands its tail loop a reader whose floor is the start of all
/// four streams, as libzstd does).
pub const DStream = struct {
    container: u64 = 0,
    bits_consumed: u32 = 0,
    buf: []const u8 = &.{},
    ptr: usize = 0,
    start: usize = 0,
    /// Set once the reader ran dry; libzstd points `ptr` at a static zero
    /// word then, which never equals `start` again.
    overflowed: bool = false,

    /// `BIT_initDStream`. Returns `src.len` like the C function.
    pub fn init(src: []const u8) Error!DStream {
        if (src.len < 1) return error.SrcSizeWrong;
        var d: DStream = .{ .buf = src };
        const last = src[src.len - 1];
        if (src.len >= 8) {
            d.ptr = src.len - 8;
            d.container = readLE64(src, d.ptr);
            d.bits_consumed = if (last != 0) 8 - highbit32(last) else 0;
            if (last == 0) return error.Generic;
        } else {
            d.ptr = 0;
            var c: u64 = src[0];
            if (src.len >= 7) c += @as(u64, src[6]) << 48;
            if (src.len >= 6) c += @as(u64, src[5]) << 40;
            if (src.len >= 5) c += @as(u64, src[4]) << 32;
            if (src.len >= 4) c += @as(u64, src[3]) << 24;
            if (src.len >= 3) c += @as(u64, src[2]) << 16;
            if (src.len >= 2) c += @as(u64, src[1]) << 8;
            d.container = c;
            d.bits_consumed = if (last != 0) 8 - highbit32(last) else 0;
            if (last == 0) return error.CorruptionDetected;
            d.bits_consumed += @intCast((8 - src.len) * 8);
        }
        return d;
    }

    /// `BIT_lookBits`: well-defined for any `bits_consumed` (the shift wraps
    /// modulo 64, as the C code masks it).
    pub inline fn lookBits(d: *const DStream, nb: u32) u64 {
        const start: u6 = @truncate(64 -% d.bits_consumed -% nb);
        return (d.container >> start) & ((@as(u64, 1) << @as(u6, @intCast(nb))) - 1);
    }

    /// `BIT_lookBitsFast`: `nb` >= 1.
    pub inline fn lookBitsFast(d: *const DStream, nb: u32) u64 {
        const l: u6 = @truncate(d.bits_consumed);
        const r: u6 = @truncate(64 -% nb);
        return (d.container << l) >> r;
    }

    pub inline fn skipBits(d: *DStream, nb: u32) void {
        d.bits_consumed += nb;
    }

    pub inline fn readBits(d: *DStream, nb: u32) u64 {
        const v = d.lookBits(nb);
        d.skipBits(nb);
        return v;
    }

    pub inline fn readBitsFast(d: *DStream, nb: u32) u64 {
        const v = d.lookBitsFast(nb);
        d.skipBits(nb);
        return v;
    }

    inline fn reloadInternal(d: *DStream) Status {
        d.ptr -= d.bits_consumed >> 3;
        d.bits_consumed &= 7;
        d.container = readLE64(d.buf, d.ptr);
        return .unfinished;
    }

    /// `BIT_reloadDStreamFast`.
    pub inline fn reloadFast(d: *DStream) Status {
        if (d.overflowed or d.ptr < d.start + 8) return .overflow;
        return d.reloadInternal();
    }

    /// `BIT_reloadDStream`.
    pub inline fn reload(d: *DStream) Status {
        if (d.bits_consumed > 64) {
            d.overflowed = true;
            return .overflow;
        }
        if (d.overflowed) return .overflow;
        if (d.ptr >= d.start + 8) return d.reloadInternal();
        if (d.ptr == d.start) {
            if (d.bits_consumed < 64) return .end_of_buffer;
            return .completed;
        }
        var nb_bytes: u32 = d.bits_consumed >> 3;
        var result: Status = .unfinished;
        if (d.ptr - d.start < nb_bytes) {
            nb_bytes = @intCast(d.ptr - d.start);
            result = .end_of_buffer;
        }
        d.ptr -= nb_bytes;
        d.bits_consumed -= nb_bytes * 8;
        d.container = readLE64(d.buf, d.ptr);
        return result;
    }

    /// `BIT_endOfDStream`.
    pub inline fn endOfStream(d: *const DStream) bool {
        return !d.overflowed and d.ptr == d.start and d.bits_consumed == 64;
    }
};

pub const tablelog_absolute_max = 15;
pub const min_tablelog = 5;

/// `FSE_readNCount`: reads a normalized-count header into `norm` (which
/// must hold `max_sv.* + 1` entries). Returns the header size; updates
/// `max_sv` to the last symbol present and sets `table_log`.
pub fn readNCount(norm: []i16, max_sv: *u32, table_log: *u32, header: []const u8) Error!usize {
    if (header.len < 8) {
        var buffer = [_]u8{0} ** 8;
        @memcpy(buffer[0..header.len], header);
        const count_size = try readNCount(norm, max_sv, table_log, &buffer);
        if (count_size > header.len) return error.CorruptionDetected;
        return count_size;
    }
    const iend = header.len;
    var ip: usize = 0;
    var charnum: u32 = 0;
    const max_sv1 = max_sv.* + 1;
    var previous0 = false;

    @memset(norm[0..max_sv1], 0);
    var bit_stream: u32 = readLE32(header, ip);
    var nb_bits: i32 = @as(i32, @intCast(bit_stream & 0xF)) + min_tablelog;
    if (nb_bits > tablelog_absolute_max) return error.TableLogTooLarge;
    bit_stream >>= 4;
    var bit_count: i32 = 4;
    table_log.* = @intCast(nb_bits);
    var remaining: i32 = (@as(i32, 1) << @intCast(nb_bits)) + 1;
    var threshold: i32 = @as(i32, 1) << @intCast(nb_bits);
    nb_bits += 1;

    while (true) {
        if (previous0) {
            var repeats: u32 = @ctz(~bit_stream | 0x80000000) >> 1;
            while (repeats >= 12) {
                charnum += 3 * 12;
                if (ip + 7 <= iend) {
                    ip += 3;
                } else {
                    bit_count -= @intCast(8 * (@as(isize, @intCast(iend)) - 7 - @as(isize, @intCast(ip))));
                    bit_count &= 31;
                    ip = iend - 4;
                }
                bit_stream = readLE32(header, ip) >> @intCast(bit_count);
                repeats = @ctz(~bit_stream | 0x80000000) >> 1;
            }
            charnum += 3 * repeats;
            bit_stream >>= @intCast(2 * repeats);
            bit_count += @intCast(2 * repeats);

            charnum += bit_stream & 3;
            bit_count += 2;

            if (charnum >= max_sv1) break;

            if (ip + 7 <= iend or ip + @as(usize, @intCast(bit_count >> 3)) + 4 <= iend) {
                ip += @intCast(bit_count >> 3);
                bit_count &= 7;
            } else {
                bit_count -= @intCast(8 * (@as(isize, @intCast(iend)) - 4 - @as(isize, @intCast(ip))));
                bit_count &= 31;
                ip = iend - 4;
            }
            bit_stream = readLE32(header, ip) >> @intCast(bit_count);
        }
        {
            const max: i32 = (2 * threshold - 1) - remaining;
            var count: i32 = undefined;
            if ((bit_stream & @as(u32, @intCast(threshold - 1))) < @as(u32, @bitCast(max))) {
                count = @intCast(bit_stream & @as(u32, @intCast(threshold - 1)));
                bit_count += nb_bits - 1;
            } else {
                count = @intCast(bit_stream & @as(u32, @intCast(2 * threshold - 1)));
                if (count >= threshold) count -= max;
                bit_count += nb_bits;
            }

            count -= 1;
            if (count >= 0) {
                remaining -= count;
            } else {
                remaining += count;
            }
            norm[charnum] = @intCast(count);
            charnum += 1;
            previous0 = count == 0;

            if (remaining < threshold) {
                if (remaining <= 1) break;
                nb_bits = @as(i32, @intCast(highbit32(@intCast(remaining)))) + 1;
                threshold = @as(i32, 1) << @intCast(nb_bits - 1);
            }
            if (charnum >= max_sv1) break;

            if (ip + 7 <= iend or ip + @as(usize, @intCast(bit_count >> 3)) + 4 <= iend) {
                ip += @intCast(bit_count >> 3);
                bit_count &= 7;
            } else {
                bit_count -= @intCast(8 * (@as(isize, @intCast(iend)) - 4 - @as(isize, @intCast(ip))));
                bit_count &= 31;
                ip = iend - 4;
            }
            bit_stream = readLE32(header, ip) >> @intCast(bit_count);
        }
    }
    if (remaining != 1) return error.CorruptionDetected;
    // Only possible when there are too many zeros.
    if (charnum > max_sv1) return error.MaxSymbolValueTooSmall;
    if (bit_count > 32) return error.CorruptionDetected;
    max_sv.* = charnum - 1;

    ip += @intCast((bit_count + 7) >> 3);
    return ip;
}

/// `FSE_TABLESTEP`.
pub inline fn tableStep(table_size: u32) u32 {
    return (table_size >> 1) + (table_size >> 3) + 3;
}

/// One cell of a byte-symbol FSE decoding table (`FSE_decode_t`).
pub const FseCell = struct { new_state: u16, symbol: u8, nb_bits: u8 };

const fse_max_symbol_value = 255;
const fse_max_tablelog = 12;

/// FSE decoding table for byte symbols; only the Huffman weight decoder
/// uses one (table log at most 6).
pub const FseDTable = struct {
    table_log: u32 = 0,
    fast_mode: bool = true,
    cells: [1 << 6]FseCell = undefined,
};

/// `FSE_buildDTable_internal` for tables up to log 6.
fn buildDTable(dt: *FseDTable, norm: []const i16, max_sv: u32, table_log: u32) Error!void {
    if (max_sv > fse_max_symbol_value) return error.Generic;
    if (table_log > 6) return error.TableLogTooLarge;
    var symbol_next: [fse_max_symbol_value + 1]u16 = undefined;
    var spread: [(1 << 6) + 8]u8 = undefined;
    const max_sv1 = max_sv + 1;
    const table_size: u32 = @as(u32, 1) << @intCast(table_log);
    var high_threshold: u32 = table_size - 1;

    dt.table_log = table_log;
    dt.fast_mode = true;
    {
        const large_limit: i16 = @intCast(@as(u32, 1) << @intCast(table_log - 1));
        var s: u32 = 0;
        while (s < max_sv1) : (s += 1) {
            if (norm[s] == -1) {
                dt.cells[high_threshold].symbol = @intCast(s);
                high_threshold -%= 1;
                symbol_next[s] = 1;
            } else {
                if (norm[s] >= large_limit) dt.fast_mode = false;
                symbol_next[s] = @bitCast(norm[s]);
            }
        }
    }

    if (high_threshold == table_size - 1) {
        const table_mask = table_size - 1;
        const step = tableStep(table_size);
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
            dt.cells[position].symbol = spread[i];
            position = (position + step) & table_mask;
        }
    } else {
        const table_mask = table_size - 1;
        const step = tableStep(table_size);
        var position: u32 = 0;
        var s: u32 = 0;
        while (s < max_sv1) : (s += 1) {
            var i: i32 = 0;
            while (i < norm[s]) : (i += 1) {
                dt.cells[position].symbol = @intCast(s);
                position = (position + step) & table_mask;
                while (position > high_threshold) position = (position + step) & table_mask;
            }
        }
        if (position != 0) return error.Generic;
    }

    var u: u32 = 0;
    while (u < table_size) : (u += 1) {
        const symbol = dt.cells[u].symbol;
        const next_state: u32 = symbol_next[symbol];
        symbol_next[symbol] += 1;
        const nb: u32 = table_log - highbit32(next_state);
        dt.cells[u].nb_bits = @intCast(nb);
        dt.cells[u].new_state = @truncate((next_state << @intCast(nb)) -% table_size);
    }
}

const DState = struct {
    state: usize,

    inline fn init(d: *DStream, dt: *const FseDTable) DState {
        const s = d.readBits(dt.table_log);
        _ = d.reload();
        return .{ .state = @intCast(s) };
    }

    inline fn decode(st: *DState, d: *DStream, dt: *const FseDTable, comptime fast: bool) u8 {
        const cell = dt.cells[st.state];
        const low = if (fast) d.readBitsFast(cell.nb_bits) else d.readBits(cell.nb_bits);
        st.state = cell.new_state + @as(usize, @intCast(low));
        return cell.symbol;
    }
};

/// `FSE_decompress_usingDTable_generic`.
fn decompressUsingDTable(dst: []u8, src: []const u8, dt: *const FseDTable, comptime fast: bool) Error!usize {
    var op: usize = 0;
    const omax = dst.len;
    const olimit = omax -% 3;

    var d = try DStream.init(src);
    var s1 = DState.init(&d, dt);
    var s2 = DState.init(&d, dt);
    if (d.reload() == .overflow) return error.CorruptionDetected;

    // 4 symbols per loop; with a 64-bit container no reload is needed in
    // between (FSE_MAX_TABLELOG*4+7 <= 64).
    while (@intFromBool(d.reload() == .unfinished) & @intFromBool(op < olimit and omax >= 3) != 0) : (op += 4) {
        dst[op + 0] = s1.decode(&d, dt, fast);
        dst[op + 1] = s2.decode(&d, dt, fast);
        dst[op + 2] = s1.decode(&d, dt, fast);
        dst[op + 3] = s2.decode(&d, dt, fast);
    }

    // tail: at this point bits_consumed <= 64 + a little
    while (true) {
        if (op + 2 > omax) return error.DstSizeTooSmall;
        dst[op] = s1.decode(&d, dt, fast);
        op += 1;
        if (d.reload() == .overflow) {
            dst[op] = s2.decode(&d, dt, fast);
            op += 1;
            break;
        }
        if (op + 2 > omax) return error.DstSizeTooSmall;
        dst[op] = s2.decode(&d, dt, fast);
        op += 1;
        if (d.reload() == .overflow) {
            dst[op] = s1.decode(&d, dt, fast);
            op += 1;
            break;
        }
    }
    return op;
}

/// `FSE_decompress_wksp_bmi2` restricted to what `HUF_readStats` needs:
/// decodes an FSE-compressed stream of Huffman weights into `dst`.
pub fn decompressWeights(dst: []u8, src: []const u8, max_log: u32) Error!usize {
    var norm: [fse_max_symbol_value + 1]i16 = undefined;
    var max_sv: u32 = fse_max_symbol_value;
    var table_log: u32 = undefined;
    const ncount_len = try readNCount(&norm, &max_sv, &table_log, src);
    if (table_log > max_log) return error.TableLogTooLarge;
    var dt: FseDTable = .{};
    try buildDTable(&dt, &norm, max_sv, table_log);
    const rest = src[ncount_len..];
    if (dt.fast_mode) return decompressUsingDTable(dst, rest, &dt, true);
    return decompressUsingDTable(dst, rest, &dt, false);
}

test "bit reader reads a stream written backwards, then reports it consumed" {
    // bits (LSB-first write order): 1 (3 bits: 101) then end mark
    // byte = 0b0000_1_101 -> highbit = 3, bitsConsumed = 5 for the 8-byte-less path
    const src = [_]u8{0b0000_1101};
    var d = try DStream.init(&src);
    try std.testing.expectEqual(@as(u32, 5 + 56), d.bits_consumed);
    try std.testing.expectEqual(@as(u64, 0b101), d.readBits(3));
    _ = d.reload();
    try std.testing.expect(d.endOfStream());
}

test "a zero last byte is not a stream" {
    try std.testing.expectError(error.CorruptionDetected, DStream.init(&.{ 1, 0 }));
    try std.testing.expectError(error.Generic, DStream.init(&.{ 1, 2, 3, 4, 5, 6, 7, 0 }));
    try std.testing.expectError(error.SrcSizeWrong, DStream.init(&.{}));
}
