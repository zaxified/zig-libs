// SPDX-License-Identifier: MIT

//! The LZMA range encoder with liblzma's symbol queue (`range_encoder.h`) and
//! the bit-price tables the optimal parser reads (`price.h`).
//!
//! The queue matters for byte parity, not only for speed: a symbol's bits are
//! queued first and only applied to the probabilities by `encode`, so the
//! length-price refresh that runs in the middle of a symbol still sees the
//! probabilities from before it.

const std = @import("std");
const c = @import("common.zig");

pub const symbols_max = 53;
pub const move_reducing_bits = 4;
pub const bit_price_shift_bits = 4;
pub const price_table_size = (1 << c.prob_bits) >> move_reducing_bits;
pub const infinity_price: u32 = 1 << 30;

/// `lzma_rc_prices`, computed the way `price_tablegen.c` does.
pub const prices: [price_table_size]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [price_table_size]u8 = undefined;
    var i: u32 = (1 << move_reducing_bits) / 2;
    while (i < (1 << c.prob_bits)) : (i += 1 << move_reducing_bits) {
        var w: u32 = i;
        var bit_count: u32 = 0;
        for (0..bit_price_shift_bits) |_| {
            w *= w;
            bit_count <<= 1;
            while (w >= (1 << 16)) {
                w >>= 1;
                bit_count += 1;
            }
        }
        t[i >> move_reducing_bits] = @intCast((c.prob_bits << bit_price_shift_bits) - 15 - bit_count);
    }
    break :blk t;
};

pub inline fn bitPrice(prob: u16, bit: u32) u32 {
    const mask: u32 = 0 -% bit;
    return prices[(@as(u32, prob) ^ (mask & ((1 << c.prob_bits) - 1))) >> move_reducing_bits];
}
pub inline fn bit0Price(prob: u16) u32 {
    return prices[prob >> move_reducing_bits];
}
pub inline fn bit1Price(prob: u16) u32 {
    return prices[(prob ^ ((1 << c.prob_bits) - 1)) >> move_reducing_bits];
}
pub inline fn bittreePrice(probs: []const u16, bit_levels: u5, symbol_in: u32) u32 {
    var price: u32 = 0;
    var symbol = symbol_in + (@as(u32, 1) << bit_levels);
    while (true) {
        const bit = symbol & 1;
        symbol >>= 1;
        price += bitPrice(probs[symbol], bit);
        if (symbol == 1) break;
    }
    return price;
}
pub inline fn bittreeReversePrice(probs: []const u16, bit_levels_in: u5, symbol_in: u32) u32 {
    return bittreeReversePriceAt(probs, 1, bit_levels_in, symbol_in);
}

/// The reverse bit tree whose model index `m` lives at `probs[at + m - 1]`
/// (liblzma points one element before `dist_special` for the short distances).
pub inline fn bittreeReversePriceAt(probs: []const u16, at: usize, bit_levels_in: u5, symbol_in: u32) u32 {
    var price: u32 = 0;
    var model: u32 = 1;
    var symbol = symbol_in;
    var levels = bit_levels_in;
    while (true) {
        const bit = symbol & 1;
        symbol >>= 1;
        price += bitPrice(probs[at + model - 1], bit);
        model = (model << 1) + bit;
        levels -= 1;
        if (levels == 0) break;
    }
    return price;
}
pub inline fn directPrice(bits: u32) u32 {
    return bits << bit_price_shift_bits;
}

const Sym = enum(u8) { bit0, bit1, direct0, direct1, flush };

pub const RangeEncoder = struct {
    low: u64 = 0,
    cache_size: u64 = 1,
    range: u32 = 0xFFFF_FFFF,
    cache: u8 = 0,
    out_total: u64 = 0,
    count: usize = 0,
    pos: usize = 0,
    syms: [symbols_max]Sym = undefined,
    probs: [symbols_max]*u16 = undefined,

    pub fn reset(rc: *RangeEncoder) void {
        rc.low = 0;
        rc.cache_size = 1;
        rc.range = 0xFFFF_FFFF;
        rc.cache = 0;
        rc.out_total = 0;
        rc.count = 0;
        rc.pos = 0;
    }

    pub inline fn bit(rc: *RangeEncoder, prob: *u16, b: u32) void {
        rc.syms[rc.count] = @fromBackingInt(@intCast(b));
        rc.probs[rc.count] = prob;
        rc.count += 1;
    }

    pub inline fn bittree(rc: *RangeEncoder, probs: []u16, bit_count_in: u5, symbol: u32) void {
        var model: u32 = 1;
        var n = bit_count_in;
        while (true) {
            n -= 1;
            const b = (symbol >> n) & 1;
            rc.bit(&probs[model], b);
            model = (model << 1) + b;
            if (n == 0) break;
        }
    }

    pub inline fn bittreeReverse(rc: *RangeEncoder, probs: []u16, bit_count_in: u5, symbol_in: u32) void {
        rc.bittreeReverseAt(probs, 1, bit_count_in, symbol_in);
    }

    pub inline fn bittreeReverseAt(rc: *RangeEncoder, probs: []u16, at: usize, bit_count_in: u5, symbol_in: u32) void {
        var model: u32 = 1;
        var n = bit_count_in;
        var symbol = symbol_in;
        while (true) {
            const b = symbol & 1;
            symbol >>= 1;
            rc.bit(&probs[at + model - 1], b);
            model = (model << 1) + b;
            n -= 1;
            if (n == 0) break;
        }
    }

    pub inline fn direct(rc: *RangeEncoder, value: u32, bit_count_in: u5) void {
        var n = bit_count_in;
        while (true) {
            n -= 1;
            rc.syms[rc.count] = @fromBackingInt(@intCast(@backingInt(Sym.direct0) + ((value >> n) & 1)));
            rc.count += 1;
            if (n == 0) break;
        }
    }

    pub fn flush(rc: *RangeEncoder) void {
        for (0..5) |_| {
            rc.syms[rc.count] = .flush;
            rc.count += 1;
        }
    }

    /// Bytes still to come out for what has been queued and shifted so far.
    pub inline fn pending(rc: *const RangeEncoder) u64 {
        return rc.cache_size + 5 - 1;
    }

    /// True when `out` is full (call again with room).
    fn shiftLow(rc: *RangeEncoder, out: []u8, out_pos: *usize) bool {
        if (@as(u32, @truncate(rc.low)) < 0xFF00_0000 or @as(u32, @truncate(rc.low >> 32)) != 0) {
            while (true) {
                if (out_pos.* == out.len) return true;
                out[out_pos.*] = rc.cache +% @as(u8, @truncate(rc.low >> 32));
                out_pos.* += 1;
                rc.out_total += 1;
                rc.cache = 0xFF;
                rc.cache_size -= 1;
                if (rc.cache_size == 0) break;
            }
            rc.cache = @truncate(rc.low >> 24);
        }
        rc.cache_size += 1;
        rc.low = (rc.low & 0x00FF_FFFF) << 8;
        return false;
    }

    /// Apply the queue to the probabilities and emit bytes. True when `out`
    /// filled up before the queue was done.
    pub fn encode(rc: *RangeEncoder, out: []u8, out_pos: *usize) bool {
        while (rc.pos < rc.count) {
            if (rc.range < c.top_value) {
                if (rc.shiftLow(out, out_pos)) return true;
                rc.range <<= 8;
            }
            switch (rc.syms[rc.pos]) {
                .bit0 => {
                    const p = rc.probs[rc.pos];
                    const prob = p.*;
                    rc.range = (rc.range >> c.prob_bits) * prob;
                    p.* = prob + (((1 << c.prob_bits) - prob) >> c.move_bits);
                },
                .bit1 => {
                    const p = rc.probs[rc.pos];
                    const prob = p.*;
                    const bound = @as(u32, prob) * (rc.range >> c.prob_bits);
                    rc.low += bound;
                    rc.range -= bound;
                    p.* = prob - (prob >> c.move_bits);
                },
                .direct0 => rc.range >>= 1,
                .direct1 => {
                    rc.range >>= 1;
                    rc.low += rc.range;
                },
                .flush => {
                    rc.range = 0xFFFF_FFFF;
                    while (true) {
                        if (rc.shiftLow(out, out_pos)) return true;
                        rc.pos += 1;
                        if (rc.pos >= rc.count) break;
                    }
                    rc.reset();
                    return false;
                },
            }
            rc.pos += 1;
        }
        rc.count = 0;
        rc.pos = 0;
        return false;
    }
};
