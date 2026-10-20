// SPDX-License-Identifier: MIT

//! The LZMA symbol encoder: a port of liblzma's `lzma_encoder.c`,
//! `lzma_encoder_optimum_fast.c` and `lzma_encoder_optimum_normal.c`. The
//! fast mode is the greedy parser with one byte of lookahead, the normal
//! mode the price-driven optimal parser over a 4096-entry window of
//! alternatives. Both ask the match finder (`lz_enc.zig`) and write through
//! the queued range encoder (`rangeenc.zig`), exactly as liblzma does, so
//! that the bytes are liblzma's.

const std = @import("std");
const c = @import("common.zig");
const rcmod = @import("rangeenc.zig");
const lz = @import("lz_enc.zig");
const RangeEncoder = rcmod.RangeEncoder;
const Mf = lz.Mf;
const Match = lz.Match;

pub const opts_max = 1 << 12;
pub const loop_input_max = opts_max + 1;
pub const lzma2_chunk_max: u32 = 1 << 16;

pub const Mode = enum { fast, normal };

pub const Options = struct {
    lc: u32 = 3,
    lp: u32 = 0,
    pb: u32 = 2,
    dict_size: u32 = 1 << 23,
    mode: Mode = .normal,
    mf: lz.MatchFinder = .bt4,
    nice_len: u32 = 64,
    /// 0 picks the finder's default from `nice_len`.
    depth: u32 = 0,

    pub fn valid(o: Options) bool {
        return o.lc <= c.lclp_max and o.lp <= c.lclp_max and o.lc + o.lp <= c.lclp_max and o.pb <= c.pb_max and
            o.nice_len >= c.match_len_min and o.nice_len <= c.match_len_max;
    }

    pub fn lzOptions(o: Options) lz.Options {
        return .{
            .before_size = opts_max,
            .dict_size = o.dict_size,
            .after_size = loop_input_max,
            .match_len_max = c.match_len_max,
            .nice_len = @max(o.mf.hashBytes(), o.nice_len),
            .match_finder = o.mf,
            .depth = o.depth,
        };
    }
};

const LenPrices = struct {
    prices: [c.pos_states_max][c.len_symbols]u32,
    table_size: u32,
    counters: [c.pos_states_max]u32,
};

const Optimal = struct {
    state: u8,
    prev_1_is_literal: bool,
    prev_2: bool,
    pos_prev_2: u32,
    back_prev_2: u32,
    price: u32,
    pos_prev: u32,
    back_prev: u32,
    backs: [c.reps]u32,
};

pub const Ret = enum { ok, stream_end };

inline fn distSlot(dist: u32) u32 {
    if (dist < 4) return dist;
    const i: u32 = 31 - @clz(dist);
    return (i + i) + ((dist >> @intCast(i - 1)) & 1);
}

inline fn literalBase(lc: u32, mask: u32, pos: u32, prev: u32) usize {
    return 3 * @as(usize, (((pos << 8) +% prev) & mask) << @intCast(lc));
}

pub const Coder = struct {
    rc: RangeEncoder = .{},
    uncomp_size: u64 = 0,
    state: u8 = 0,
    reps: [c.reps]u32 = .{ 0, 0, 0, 0 },
    matches: [c.match_len_max + 1]Match = undefined,
    matches_count: u32 = 0,
    longest_match_length: u32 = 0,
    fast_mode: bool = false,
    is_initialized: bool = false,
    is_flushed: bool = false,
    use_eopm: bool = false,
    pos_mask: u32 = 0,
    literal_context_bits: u32 = 0,
    literal_mask: u32 = 0,
    probs: c.Probs = undefined,
    match_len: LenPrices = undefined,
    rep_len: LenPrices = undefined,
    dist_slot_prices: [c.dist_states][c.dist_slots]u32 = undefined,
    dist_prices: [c.dist_states][c.full_distances]u32 = undefined,
    dist_table_size: u32 = 0,
    match_price_count: u32 = 0,
    align_prices: [c.align_size]u32 = undefined,
    align_price_count: u32 = 0,
    opts_end_index: u32 = 0,
    opts_current_index: u32 = 0,
    opts: [opts_max]Optimal = undefined,

    /// `lzma_lzma_encoder_create` + reset. `use_eopm` is for LZMA1 streams.
    pub fn init(co: *Coder, o: Options, use_eopm: bool) error{OptionsError}!void {
        if (!o.valid()) return error.OptionsError;
        co.fast_mode = o.mode == .fast;
        if (!co.fast_mode) {
            if (o.dict_size > lz.dict_size_max) return error.OptionsError;
            var log_size: u5 = 0;
            while ((@as(u64, 1) << log_size) < o.dict_size) log_size += 1;
            co.dist_table_size = @as(u32, log_size) * 2;
            const nice_len = @max(o.mf.hashBytes(), o.nice_len);
            co.match_len.table_size = nice_len + 1 - c.match_len_min;
            co.rep_len.table_size = nice_len + 1 - c.match_len_min;
        }
        co.is_initialized = false;
        co.is_flushed = false;
        co.uncomp_size = 0;
        co.use_eopm = use_eopm;
        co.reset(o);
    }

    /// `lzma_lzma_encoder_reset`: a state reset (LZMA2 does this between chunks).
    pub fn reset(co: *Coder, o: Options) void {
        co.pos_mask = (@as(u32, 1) << @intCast(o.pb)) - 1;
        co.literal_context_bits = o.lc;
        co.literal_mask = (@as(u32, 0x100) << @intCast(o.lp)) - (@as(u32, 0x100) >> @intCast(o.lc));
        co.rc.reset();
        co.state = 0;
        co.reps = .{ 0, 0, 0, 0 };
        co.probs.reset(o.lc, o.lp);
        if (!co.fast_mode) {
            const n = @as(u32, 1) << @intCast(o.pb);
            for (0..n) |ps| {
                lenUpdatePrices(&co.match_len, &co.probs.match_len, @intCast(ps));
                lenUpdatePrices(&co.rep_len, &co.probs.rep_len, @intCast(ps));
            }
        }
        co.match_price_count = std.math.maxInt(u32) / 2;
        co.align_price_count = std.math.maxInt(u32) / 2;
        co.opts_end_index = 0;
        co.opts_current_index = 0;
    }

    // ── symbol coding ───────────────────────────────────────────────────

    fn literal(co: *Coder, mf: *const Mf, position: u32) void {
        const idx = mf.read_pos - mf.read_ahead;
        const cur_byte: u32 = mf.buffer[idx];
        const base = literalBase(co.literal_context_bits, co.literal_mask, position, mf.buffer[idx - 1]);
        const sub = co.probs.literal[base..][0..c.literal_coder_size];
        if (c.isLiteralState(co.state)) {
            co.state = c.updateLiteral(co.state);
            co.rc.bittree(sub, 8, cur_byte);
        } else {
            co.state = c.updateLiteral(co.state);
            const match_byte: u32 = mf.buffer[idx - co.reps[0] - 1];
            literalMatched(&co.rc, sub, match_byte, cur_byte);
        }
    }

    fn literalMatched(rc: *RangeEncoder, sub: []u16, match_byte_in: u32, symbol_in: u32) void {
        var match_byte = match_byte_in;
        var offset: u32 = 0x100;
        var symbol = symbol_in + (@as(u32, 1) << 8);
        while (true) {
            match_byte <<= 1;
            const match_bit = match_byte & offset;
            const sub_index = offset + match_bit + (symbol >> 8);
            const b = (symbol >> 7) & 1;
            rc.bit(&sub[sub_index], b);
            symbol <<= 1;
            offset &= ~(match_byte ^ symbol);
            if (symbol >= (1 << 16)) break;
        }
    }

    fn length(co: *Coder, lp: *c.LenProbs, pr: *LenPrices, pos_state: u32, len_in: u32) void {
        var len = len_in - c.match_len_min;
        const rc = &co.rc;
        if (len < c.len_low_symbols) {
            rc.bit(&lp.choice, 0);
            rc.bittree(&lp.low[pos_state], 3, len);
        } else {
            rc.bit(&lp.choice, 1);
            len -= c.len_low_symbols;
            if (len < c.len_mid_symbols) {
                rc.bit(&lp.choice2, 0);
                rc.bittree(&lp.mid[pos_state], 3, len);
            } else {
                rc.bit(&lp.choice2, 1);
                len -= c.len_mid_symbols;
                rc.bittree(&lp.high, 8, len);
            }
        }
        if (!co.fast_mode) {
            pr.counters[pos_state] -= 1;
            if (pr.counters[pos_state] == 0) lenUpdatePrices(pr, lp, pos_state);
        }
    }

    fn match(co: *Coder, pos_state: u32, distance: u32, len: u32) void {
        co.state = c.updateMatch(co.state);
        co.length(&co.probs.match_len, &co.match_len, pos_state, len);
        const slot = distSlot(distance);
        const dist_state = c.distState(len);
        co.rc.bittree(&co.probs.dist_slot[dist_state], c.dist_slot_bits, slot);
        if (slot >= c.dist_model_start) {
            const footer_bits: u5 = @intCast((slot >> 1) - 1);
            const base = (2 | (slot & 1)) << footer_bits;
            const dist_reduced = distance -% base;
            if (slot < c.dist_model_end) {
                co.rc.bittreeReverseAt(&co.probs.pos_special, base - slot, footer_bits, dist_reduced);
            } else {
                co.rc.direct(dist_reduced >> c.align_bits, footer_bits - c.align_bits);
                co.rc.bittreeReverse(&co.probs.pos_align, c.align_bits, dist_reduced & (c.align_size - 1));
                co.align_price_count +%= 1;
            }
        }
        co.reps[3] = co.reps[2];
        co.reps[2] = co.reps[1];
        co.reps[1] = co.reps[0];
        co.reps[0] = distance;
        co.match_price_count +%= 1;
    }

    fn repMatch(co: *Coder, pos_state: u32, rep: u32, len: u32) void {
        const st = co.state;
        if (rep == 0) {
            co.rc.bit(&co.probs.is_rep0[st], 0);
            co.rc.bit(&co.probs.is_rep0_long[st][pos_state], @intFromBool(len != 1));
        } else {
            const distance = co.reps[rep];
            co.rc.bit(&co.probs.is_rep0[st], 1);
            if (rep == 1) {
                co.rc.bit(&co.probs.is_rep1[st], 0);
            } else {
                co.rc.bit(&co.probs.is_rep1[st], 1);
                co.rc.bit(&co.probs.is_rep2[st], rep - 2);
                if (rep == 3) co.reps[3] = co.reps[2];
                co.reps[2] = co.reps[1];
            }
            co.reps[1] = co.reps[0];
            co.reps[0] = distance;
        }
        if (len == 1) {
            co.state = c.updateShortRep(co.state);
        } else {
            co.length(&co.probs.rep_len, &co.rep_len, pos_state, len);
            co.state = c.updateLongRep(co.state);
        }
    }

    fn encodeSymbol(co: *Coder, mf: *Mf, back: u32, len: u32, position: u32) void {
        const pos_state = position & co.pos_mask;
        if (back == std.math.maxInt(u32)) {
            co.rc.bit(&co.probs.is_match[co.state][pos_state], 0);
            co.literal(mf, position);
        } else {
            co.rc.bit(&co.probs.is_match[co.state][pos_state], 1);
            if (back < c.reps) {
                co.rc.bit(&co.probs.is_rep[co.state], 1);
                co.repMatch(pos_state, back, len);
            } else {
                co.rc.bit(&co.probs.is_rep[co.state], 0);
                co.match(pos_state, back - c.reps, len);
            }
        }
        mf.read_ahead -= len;
    }

    fn encodeInit(co: *Coder, mf: *Mf) bool {
        if (mf.read_pos == mf.read_limit) {
            if (mf.action == .run) return false;
        } else {
            mf.skipRa(1);
            mf.read_ahead = 0;
            co.rc.bit(&co.probs.is_match[0][0], 0);
            co.rc.bittree(co.probs.literal[0..c.literal_coder_size], 8, mf.buffer[0]);
            co.uncomp_size += 1;
        }
        co.is_initialized = true;
        return true;
    }

    fn encodeEopm(co: *Coder, position: u32) void {
        const pos_state = position & co.pos_mask;
        co.rc.bit(&co.probs.is_match[co.state][pos_state], 1);
        co.rc.bit(&co.probs.is_rep[co.state], 0);
        co.match(pos_state, std.math.maxInt(u32), c.match_len_min);
    }

    /// `lzma_lzma_encode`. `limit` is maxInt(u32) for LZMA1; LZMA2 passes the
    /// position at which the chunk must end.
    pub fn encode(co: *Coder, mf: *Mf, out: []u8, out_pos: *usize, limit: u32) Ret {
        if (!co.is_initialized and !co.encodeInit(mf)) return .ok;
        if (co.rc.encode(out, out_pos)) return .ok;
        if (co.is_flushed) return .stream_end;

        while (true) {
            if (limit != std.math.maxInt(u32) and
                (mf.read_pos - mf.read_ahead >= limit or
                    out_pos.* + co.rc.pending() >= lzma2_chunk_max - loop_input_max))
                break;
            if (mf.read_pos >= mf.read_limit) {
                if (mf.action == .run) return .ok;
                if (mf.read_ahead == 0) break;
            }
            var len: u32 = undefined;
            var back: u32 = undefined;
            if (co.fast_mode) {
                co.optimumFast(mf, &back, &len);
            } else {
                co.optimumNormal(mf, &back, &len, @truncate(co.uncomp_size));
            }
            co.encodeSymbol(mf, back, len, @truncate(co.uncomp_size));
            co.uncomp_size += len;
            if (co.rc.encode(out, out_pos)) return .ok;
        }
        if (co.use_eopm) co.encodeEopm(@truncate(co.uncomp_size));
        co.rc.flush();
        if (co.rc.encode(out, out_pos)) {
            co.is_flushed = true;
            return .ok;
        }
        return .stream_end;
    }

    // ── the fast parser ─────────────────────────────────────────────────

    inline fn changePair(small_dist: u32, big_dist: u32) bool {
        return (big_dist >> 7) > small_dist;
    }

    inline fn notEqual16(mf: *const Mf, a: usize, b: usize) bool {
        return mf.buffer[a] != mf.buffer[b] or mf.buffer[a + 1] != mf.buffer[b + 1];
    }

    fn optimumFast(co: *Coder, mf: *Mf, back_res: *u32, len_res: *u32) void {
        const nice_len = mf.nice_len;
        var len_main: u32 = undefined;
        var matches_count: u32 = undefined;
        if (mf.read_ahead == 0) {
            len_main = mf.find(&matches_count, &co.matches);
        } else {
            len_main = co.longest_match_length;
            matches_count = co.matches_count;
        }
        const buf: usize = mf.read_pos - 1;
        const buf_avail = @min(mf.avail() + 1, c.match_len_max);
        if (buf_avail < 2) {
            back_res.* = std.math.maxInt(u32);
            len_res.* = 1;
            return;
        }
        var rep_len: u32 = 0;
        var rep_index: u32 = 0;
        for (0..c.reps) |i| {
            const buf_back = buf - co.reps[i] - 1;
            if (notEqual16(mf, buf, buf_back)) continue;
            const len = mf.memcmplen(buf, buf_back, 2, buf_avail);
            if (len >= nice_len) {
                back_res.* = @intCast(i);
                len_res.* = len;
                mf.skipRa(len - 1);
                return;
            }
            if (len > rep_len) {
                rep_index = @intCast(i);
                rep_len = len;
            }
        }
        if (len_main >= nice_len) {
            back_res.* = co.matches[matches_count - 1].dist + c.reps;
            len_res.* = len_main;
            mf.skipRa(len_main - 1);
            return;
        }
        var back_main: u32 = 0;
        if (len_main >= 2) {
            back_main = co.matches[matches_count - 1].dist;
            while (matches_count > 1 and len_main == co.matches[matches_count - 2].len + 1) {
                if (!changePair(co.matches[matches_count - 2].dist, back_main)) break;
                matches_count -= 1;
                len_main = co.matches[matches_count - 1].len;
                back_main = co.matches[matches_count - 1].dist;
            }
            if (len_main == 2 and back_main >= 0x80) len_main = 1;
        }
        if (rep_len >= 2) {
            if (rep_len + 1 >= len_main or
                (rep_len + 2 >= len_main and back_main > (1 << 9)) or
                (rep_len + 3 >= len_main and back_main > (1 << 15)))
            {
                back_res.* = rep_index;
                len_res.* = rep_len;
                mf.skipRa(rep_len - 1);
                return;
            }
        }
        if (len_main < 2 or buf_avail <= 2) {
            back_res.* = std.math.maxInt(u32);
            len_res.* = 1;
            return;
        }
        co.longest_match_length = mf.find(&co.matches_count, &co.matches);
        if (co.longest_match_length >= 2) {
            const new_dist = co.matches[co.matches_count - 1].dist;
            if ((co.longest_match_length >= len_main and new_dist < back_main) or
                (co.longest_match_length == len_main + 1 and !changePair(back_main, new_dist)) or
                (co.longest_match_length > len_main + 1) or
                (co.longest_match_length + 1 >= len_main and len_main >= 3 and changePair(new_dist, back_main)))
            {
                back_res.* = std.math.maxInt(u32);
                len_res.* = 1;
                return;
            }
        }
        const b1 = buf + 1;
        const limit = @max(2, len_main - 1);
        for (0..c.reps) |i| {
            const bb = b1 - co.reps[i] - 1;
            if (std.mem.eql(u8, mf.buffer[b1..][0..limit], mf.buffer[bb..][0..limit])) {
                back_res.* = std.math.maxInt(u32);
                len_res.* = 1;
                return;
            }
        }
        back_res.* = back_main + c.reps;
        len_res.* = len_main;
        mf.skipRa(len_main - 2);
    }

    // ── prices ──────────────────────────────────────────────────────────

    fn lenUpdatePrices(pr: *LenPrices, lp: *const c.LenProbs, pos_state: u32) void {
        const table_size = pr.table_size;
        pr.counters[pos_state] = table_size;
        const a0 = rcmod.bit0Price(lp.choice);
        const a1 = rcmod.bit1Price(lp.choice);
        const b0 = a1 + rcmod.bit0Price(lp.choice2);
        const b1 = a1 + rcmod.bit1Price(lp.choice2);
        const prices = &pr.prices[pos_state];
        var i: u32 = 0;
        while (i < table_size and i < c.len_low_symbols) : (i += 1)
            prices[i] = a0 + rcmod.bittreePrice(&lp.low[pos_state], 3, i);
        while (i < table_size and i < c.len_low_symbols + c.len_mid_symbols) : (i += 1)
            prices[i] = b0 + rcmod.bittreePrice(&lp.mid[pos_state], 3, i - c.len_low_symbols);
        while (i < table_size) : (i += 1)
            prices[i] = b1 + rcmod.bittreePrice(&lp.high, 8, i - c.len_low_symbols - c.len_mid_symbols);
    }

    fn literalPrice(co: *const Coder, pos: u32, prev_byte: u32, match_mode: bool, match_byte_in: u32, symbol_in: u32) u32 {
        const base = literalBase(co.literal_context_bits, co.literal_mask, pos, prev_byte);
        const sub = co.probs.literal[base..][0..c.literal_coder_size];
        var price: u32 = 0;
        if (!match_mode) {
            price = rcmod.bittreePrice(sub, 8, symbol_in);
        } else {
            var match_byte = match_byte_in;
            var offset: u32 = 0x100;
            var symbol = symbol_in + (@as(u32, 1) << 8);
            while (true) {
                match_byte <<= 1;
                const match_bit = match_byte & offset;
                const sub_index = offset + match_bit + (symbol >> 8);
                const b = (symbol >> 7) & 1;
                price += rcmod.bitPrice(sub[sub_index], b);
                symbol <<= 1;
                offset &= ~(match_byte ^ symbol);
                if (symbol >= (1 << 16)) break;
            }
        }
        return price;
    }

    inline fn lenPrice(pr: *const LenPrices, len: u32, pos_state: u32) u32 {
        return pr.prices[pos_state][len - c.match_len_min];
    }

    inline fn shortRepPrice(co: *const Coder, state: u8, pos_state: u32) u32 {
        return rcmod.bit0Price(co.probs.is_rep0[state]) + rcmod.bit0Price(co.probs.is_rep0_long[state][pos_state]);
    }

    inline fn pureRepPrice(co: *const Coder, rep_index: u32, state: u8, pos_state: u32) u32 {
        var price: u32 = undefined;
        if (rep_index == 0) {
            price = rcmod.bit0Price(co.probs.is_rep0[state]);
            price += rcmod.bit1Price(co.probs.is_rep0_long[state][pos_state]);
        } else {
            price = rcmod.bit1Price(co.probs.is_rep0[state]);
            if (rep_index == 1) {
                price += rcmod.bit0Price(co.probs.is_rep1[state]);
            } else {
                price += rcmod.bit1Price(co.probs.is_rep1[state]);
                price += rcmod.bitPrice(co.probs.is_rep2[state], rep_index - 2);
            }
        }
        return price;
    }

    inline fn repPrice(co: *const Coder, rep_index: u32, len: u32, state: u8, pos_state: u32) u32 {
        return lenPrice(&co.rep_len, len, pos_state) + co.pureRepPrice(rep_index, state, pos_state);
    }

    inline fn distLenPrice(co: *const Coder, dist: u32, len: u32, pos_state: u32) u32 {
        const dist_state = c.distState(len);
        var price: u32 = undefined;
        if (dist < c.full_distances) {
            price = co.dist_prices[dist_state][dist];
        } else {
            const slot = distSlot(dist);
            price = co.dist_slot_prices[dist_state][slot] + co.align_prices[dist & (c.align_size - 1)];
        }
        price += lenPrice(&co.match_len, len, pos_state);
        return price;
    }

    fn fillDistPrices(co: *Coder) void {
        for (0..c.dist_states) |ds| {
            const slot_prices = &co.dist_slot_prices[ds];
            var slot: u32 = 0;
            while (slot < co.dist_table_size) : (slot += 1)
                slot_prices[slot] = rcmod.bittreePrice(&co.probs.dist_slot[ds], c.dist_slot_bits, slot);
            slot = c.dist_model_end;
            while (slot < co.dist_table_size) : (slot += 1)
                slot_prices[slot] += rcmod.directPrice(((slot >> 1) - 1) - c.align_bits);
            for (0..c.dist_model_start) |i| co.dist_prices[ds][i] = slot_prices[i];
        }
        var i: u32 = c.dist_model_start;
        while (i < c.full_distances) : (i += 1) {
            const slot = distSlot(i);
            const footer_bits: u5 = @intCast((slot >> 1) - 1);
            const base = (2 | (slot & 1)) << footer_bits;
            const price = rcmod.bittreeReversePriceAt(&co.probs.pos_special, base - slot, footer_bits, i - base);
            for (0..c.dist_states) |ds| co.dist_prices[ds][i] = price + co.dist_slot_prices[ds][slot];
        }
        co.match_price_count = 0;
    }

    fn fillAlignPrices(co: *Coder) void {
        for (0..c.align_size) |i|
            co.align_prices[i] = rcmod.bittreeReversePrice(&co.probs.pos_align, c.align_bits, @intCast(i));
        co.align_price_count = 0;
    }

    // ── the optimal parser ──────────────────────────────────────────────

    inline fn makeLiteral(o: *Optimal) void {
        o.back_prev = std.math.maxInt(u32);
        o.prev_1_is_literal = false;
    }
    inline fn makeShortRep(o: *Optimal) void {
        o.back_prev = 0;
        o.prev_1_is_literal = false;
    }
    inline fn isShortRep(o: *const Optimal) bool {
        return o.back_prev == 0;
    }

    fn backward(co: *Coder, len_res: *u32, back_res: *u32, cur_in: u32) void {
        var cur = cur_in;
        co.opts_end_index = cur;
        var pos_mem = co.opts[cur].pos_prev;
        var back_mem = co.opts[cur].back_prev;
        while (true) {
            if (co.opts[cur].prev_1_is_literal) {
                makeLiteral(&co.opts[pos_mem]);
                co.opts[pos_mem].pos_prev = pos_mem - 1;
                if (co.opts[cur].prev_2) {
                    co.opts[pos_mem - 1].prev_1_is_literal = false;
                    co.opts[pos_mem - 1].pos_prev = co.opts[cur].pos_prev_2;
                    co.opts[pos_mem - 1].back_prev = co.opts[cur].back_prev_2;
                }
            }
            const pos_prev = pos_mem;
            const back_cur = back_mem;
            back_mem = co.opts[pos_prev].back_prev;
            pos_mem = co.opts[pos_prev].pos_prev;
            co.opts[pos_prev].back_prev = back_cur;
            co.opts[pos_prev].pos_prev = cur;
            cur = pos_prev;
            if (cur == 0) break;
        }
        co.opts_current_index = co.opts[0].pos_prev;
        len_res.* = co.opts[0].pos_prev;
        back_res.* = co.opts[0].back_prev;
    }

    /// Returns len_end, or maxInt(u32) when the decision is already made.
    fn helper1(co: *Coder, mf: *Mf, back_res: *u32, len_res: *u32, position: u32) u32 {
        const nice_len = mf.nice_len;
        var len_main: u32 = undefined;
        var matches_count: u32 = undefined;
        if (mf.read_ahead == 0) {
            len_main = mf.find(&matches_count, &co.matches);
        } else {
            len_main = co.longest_match_length;
            matches_count = co.matches_count;
        }
        const buf_avail = @min(mf.avail() + 1, c.match_len_max);
        if (buf_avail < 2) {
            back_res.* = std.math.maxInt(u32);
            len_res.* = 1;
            return std.math.maxInt(u32);
        }
        const buf: usize = mf.read_pos - 1;
        var rep_lens: [c.reps]u32 = undefined;
        var rep_max_index: u32 = 0;
        for (0..c.reps) |i| {
            const buf_back = buf - co.reps[i] - 1;
            if (notEqual16(mf, buf, buf_back)) {
                rep_lens[i] = 0;
                continue;
            }
            rep_lens[i] = mf.memcmplen(buf, buf_back, 2, buf_avail);
            if (rep_lens[i] > rep_lens[rep_max_index]) rep_max_index = @intCast(i);
        }
        if (rep_lens[rep_max_index] >= nice_len) {
            back_res.* = rep_max_index;
            len_res.* = rep_lens[rep_max_index];
            mf.skipRa(len_res.* - 1);
            return std.math.maxInt(u32);
        }
        if (len_main >= nice_len) {
            back_res.* = co.matches[matches_count - 1].dist + c.reps;
            len_res.* = len_main;
            mf.skipRa(len_main - 1);
            return std.math.maxInt(u32);
        }
        const current_byte: u32 = mf.buffer[buf];
        const match_byte: u32 = mf.buffer[buf - co.reps[0] - 1];
        if (len_main < 2 and current_byte != match_byte and rep_lens[rep_max_index] < 2) {
            back_res.* = std.math.maxInt(u32);
            len_res.* = 1;
            return std.math.maxInt(u32);
        }
        co.opts[0].state = co.state;
        const pos_state = position & co.pos_mask;
        co.opts[1].price = rcmod.bit0Price(co.probs.is_match[co.state][pos_state]) +
            co.literalPrice(position, mf.buffer[buf - 1], !c.isLiteralState(co.state), match_byte, current_byte);
        makeLiteral(&co.opts[1]);
        const match_price = rcmod.bit1Price(co.probs.is_match[co.state][pos_state]);
        const rep_match_price = match_price + rcmod.bit1Price(co.probs.is_rep[co.state]);
        if (match_byte == current_byte) {
            const short_rep_price = rep_match_price + co.shortRepPrice(co.state, pos_state);
            if (short_rep_price < co.opts[1].price) {
                co.opts[1].price = short_rep_price;
                makeShortRep(&co.opts[1]);
            }
        }
        const len_end = @max(len_main, rep_lens[rep_max_index]);
        if (len_end < 2) {
            back_res.* = co.opts[1].back_prev;
            len_res.* = 1;
            return std.math.maxInt(u32);
        }
        co.opts[1].pos_prev = 0;
        for (0..c.reps) |i| co.opts[0].backs[i] = co.reps[i];
        var len = len_end;
        while (true) {
            co.opts[len].price = rcmod.infinity_price;
            len -= 1;
            if (len < 2) break;
        }
        for (0..c.reps) |i| {
            var rep_len = rep_lens[i];
            if (rep_len < 2) continue;
            const price = rep_match_price + co.pureRepPrice(@intCast(i), co.state, pos_state);
            while (true) {
                const cur_and_len_price = price + lenPrice(&co.rep_len, rep_len, pos_state);
                if (cur_and_len_price < co.opts[rep_len].price) {
                    co.opts[rep_len].price = cur_and_len_price;
                    co.opts[rep_len].pos_prev = 0;
                    co.opts[rep_len].back_prev = @intCast(i);
                    co.opts[rep_len].prev_1_is_literal = false;
                }
                rep_len -= 1;
                if (rep_len < 2) break;
            }
        }
        const normal_match_price = match_price + rcmod.bit0Price(co.probs.is_rep[co.state]);
        len = if (rep_lens[0] >= 2) rep_lens[0] + 1 else 2;
        if (len <= len_main) {
            var i: u32 = 0;
            while (len > co.matches[i].len) i += 1;
            while (true) : (len += 1) {
                const dist = co.matches[i].dist;
                const cur_and_len_price = normal_match_price + co.distLenPrice(dist, len, pos_state);
                if (cur_and_len_price < co.opts[len].price) {
                    co.opts[len].price = cur_and_len_price;
                    co.opts[len].pos_prev = 0;
                    co.opts[len].back_prev = dist + c.reps;
                    co.opts[len].prev_1_is_literal = false;
                }
                if (len == co.matches[i].len) {
                    i += 1;
                    if (i == matches_count) break;
                }
            }
        }
        return len_end;
    }

    fn helper2(co: *Coder, mf: *const Mf, reps: *[c.reps]u32, buf: usize, len_end_in: u32, position: u32, cur: u32, nice_len: u32, buf_avail_full: u32) u32 {
        var len_end = len_end_in;
        var matches_count = co.matches_count;
        var new_len = co.longest_match_length;
        var pos_prev = co.opts[cur].pos_prev;
        var state: u8 = undefined;
        if (co.opts[cur].prev_1_is_literal) {
            pos_prev -= 1;
            if (co.opts[cur].prev_2) {
                state = co.opts[co.opts[cur].pos_prev_2].state;
                if (co.opts[cur].back_prev_2 < c.reps) state = c.updateLongRep(state) else state = c.updateMatch(state);
            } else {
                state = co.opts[pos_prev].state;
            }
            state = c.updateLiteral(state);
        } else {
            state = co.opts[pos_prev].state;
        }
        if (pos_prev == cur - 1) {
            if (isShortRep(&co.opts[cur])) state = c.updateShortRep(state) else state = c.updateLiteral(state);
        } else {
            var pos: u32 = undefined;
            if (co.opts[cur].prev_1_is_literal and co.opts[cur].prev_2) {
                pos_prev = co.opts[cur].pos_prev_2;
                pos = co.opts[cur].back_prev_2;
                state = c.updateLongRep(state);
            } else {
                pos = co.opts[cur].back_prev;
                if (pos < c.reps) state = c.updateLongRep(state) else state = c.updateMatch(state);
            }
            if (pos < c.reps) {
                reps[0] = co.opts[pos_prev].backs[pos];
                var i: u32 = 1;
                while (i <= pos) : (i += 1) reps[i] = co.opts[pos_prev].backs[i - 1];
                while (i < c.reps) : (i += 1) reps[i] = co.opts[pos_prev].backs[i];
            } else {
                reps[0] = pos - c.reps;
                for (1..c.reps) |i| reps[i] = co.opts[pos_prev].backs[i - 1];
            }
        }
        co.opts[cur].state = state;
        for (0..c.reps) |i| co.opts[cur].backs[i] = reps[i];
        const cur_price = co.opts[cur].price;
        const current_byte: u32 = mf.buffer[buf];
        const match_byte: u32 = mf.buffer[buf - reps[0] - 1];
        const pos_state = position & co.pos_mask;
        const cur_and_1_price = cur_price + rcmod.bit0Price(co.probs.is_match[state][pos_state]) +
            co.literalPrice(position, mf.buffer[buf - 1], !c.isLiteralState(state), match_byte, current_byte);
        var next_is_literal = false;
        if (cur_and_1_price < co.opts[cur + 1].price) {
            co.opts[cur + 1].price = cur_and_1_price;
            co.opts[cur + 1].pos_prev = cur;
            makeLiteral(&co.opts[cur + 1]);
            next_is_literal = true;
        }
        const match_price = cur_price + rcmod.bit1Price(co.probs.is_match[state][pos_state]);
        const rep_match_price = match_price + rcmod.bit1Price(co.probs.is_rep[state]);
        if (match_byte == current_byte and !(co.opts[cur + 1].pos_prev < cur and co.opts[cur + 1].back_prev == 0)) {
            const short_rep_price = rep_match_price + co.shortRepPrice(state, pos_state);
            if (short_rep_price <= co.opts[cur + 1].price) {
                co.opts[cur + 1].price = short_rep_price;
                co.opts[cur + 1].pos_prev = cur;
                makeShortRep(&co.opts[cur + 1]);
                next_is_literal = true;
            }
        }
        if (buf_avail_full < 2) return len_end;
        const buf_avail = @min(buf_avail_full, nice_len);
        if (!next_is_literal and match_byte != current_byte) {
            const buf_back = buf - reps[0] - 1;
            const limit = @min(buf_avail_full, nice_len + 1);
            const len_test = mf.memcmplen(buf, buf_back, 1, limit) - 1;
            if (len_test >= 2) {
                const state_2 = c.updateLiteral(state);
                const pos_state_next = (position + 1) & co.pos_mask;
                const next_rep_match_price = cur_and_1_price +
                    rcmod.bit1Price(co.probs.is_match[state_2][pos_state_next]) +
                    rcmod.bit1Price(co.probs.is_rep[state_2]);
                const offset = cur + 1 + len_test;
                while (len_end < offset) {
                    len_end += 1;
                    co.opts[len_end].price = rcmod.infinity_price;
                }
                const cur_and_len_price = next_rep_match_price + co.repPrice(0, len_test, state_2, pos_state_next);
                if (cur_and_len_price < co.opts[offset].price) {
                    co.opts[offset].price = cur_and_len_price;
                    co.opts[offset].pos_prev = cur + 1;
                    co.opts[offset].back_prev = 0;
                    co.opts[offset].prev_1_is_literal = true;
                    co.opts[offset].prev_2 = false;
                }
            }
        }
        var start_len: u32 = 2;
        for (0..c.reps) |rep_index_usize| {
            const rep_index: u32 = @intCast(rep_index_usize);
            const buf_back = buf - reps[rep_index] - 1;
            if (notEqual16(mf, buf, buf_back)) continue;
            var len_test = mf.memcmplen(buf, buf_back, 2, buf_avail);
            while (len_end < cur + len_test) {
                len_end += 1;
                co.opts[len_end].price = rcmod.infinity_price;
            }
            const len_test_temp = len_test;
            const price = rep_match_price + co.pureRepPrice(rep_index, state, pos_state);
            while (true) {
                const cur_and_len_price = price + lenPrice(&co.rep_len, len_test, pos_state);
                if (cur_and_len_price < co.opts[cur + len_test].price) {
                    co.opts[cur + len_test].price = cur_and_len_price;
                    co.opts[cur + len_test].pos_prev = cur;
                    co.opts[cur + len_test].back_prev = rep_index;
                    co.opts[cur + len_test].prev_1_is_literal = false;
                }
                len_test -= 1;
                if (len_test < 2) break;
            }
            len_test = len_test_temp;
            if (rep_index == 0) start_len = len_test + 1;
            var len_test_2 = len_test + 1;
            const limit = @min(buf_avail_full, len_test_2 + nice_len);
            if (len_test_2 < limit) len_test_2 = mf.memcmplen(buf, buf_back, len_test_2, limit);
            len_test_2 -= len_test + 1;
            if (len_test_2 >= 2) {
                var state_2 = c.updateLongRep(state);
                var pos_state_next = (position + len_test) & co.pos_mask;
                const cur_and_len_literal_price = price + lenPrice(&co.rep_len, len_test, pos_state) +
                    rcmod.bit0Price(co.probs.is_match[state_2][pos_state_next]) +
                    co.literalPrice(position + len_test, mf.buffer[buf + len_test - 1], true, mf.buffer[buf_back + len_test], mf.buffer[buf + len_test]);
                state_2 = c.updateLiteral(state_2);
                pos_state_next = (position + len_test + 1) & co.pos_mask;
                const next_rep_match_price = cur_and_len_literal_price +
                    rcmod.bit1Price(co.probs.is_match[state_2][pos_state_next]) +
                    rcmod.bit1Price(co.probs.is_rep[state_2]);
                const offset = cur + len_test + 1 + len_test_2;
                while (len_end < offset) {
                    len_end += 1;
                    co.opts[len_end].price = rcmod.infinity_price;
                }
                const cur_and_len_price = next_rep_match_price + co.repPrice(0, len_test_2, state_2, pos_state_next);
                if (cur_and_len_price < co.opts[offset].price) {
                    co.opts[offset].price = cur_and_len_price;
                    co.opts[offset].pos_prev = cur + len_test + 1;
                    co.opts[offset].back_prev = 0;
                    co.opts[offset].prev_1_is_literal = true;
                    co.opts[offset].prev_2 = true;
                    co.opts[offset].pos_prev_2 = cur;
                    co.opts[offset].back_prev_2 = rep_index;
                }
            }
        }
        if (new_len > buf_avail) {
            new_len = buf_avail;
            matches_count = 0;
            while (new_len > co.matches[matches_count].len) matches_count += 1;
            co.matches[matches_count].len = new_len;
            matches_count += 1;
        }
        if (new_len >= start_len) {
            const normal_match_price = match_price + rcmod.bit0Price(co.probs.is_rep[state]);
            while (len_end < cur + new_len) {
                len_end += 1;
                co.opts[len_end].price = rcmod.infinity_price;
            }
            var i: u32 = 0;
            while (start_len > co.matches[i].len) i += 1;
            var len_test = start_len;
            while (true) : (len_test += 1) {
                const cur_back = co.matches[i].dist;
                var cur_and_len_price = normal_match_price + co.distLenPrice(cur_back, len_test, pos_state);
                if (cur_and_len_price < co.opts[cur + len_test].price) {
                    co.opts[cur + len_test].price = cur_and_len_price;
                    co.opts[cur + len_test].pos_prev = cur;
                    co.opts[cur + len_test].back_prev = cur_back + c.reps;
                    co.opts[cur + len_test].prev_1_is_literal = false;
                }
                if (len_test == co.matches[i].len) {
                    const buf_back = buf - cur_back - 1;
                    var len_test_2 = len_test + 1;
                    const limit = @min(buf_avail_full, len_test_2 + nice_len);
                    if (len_test_2 < limit) len_test_2 = mf.memcmplen(buf, buf_back, len_test_2, limit);
                    len_test_2 -= len_test + 1;
                    if (len_test_2 >= 2) {
                        var state_2 = c.updateMatch(state);
                        var pos_state_next = (position + len_test) & co.pos_mask;
                        const cur_and_len_literal_price = cur_and_len_price +
                            rcmod.bit0Price(co.probs.is_match[state_2][pos_state_next]) +
                            co.literalPrice(position + len_test, mf.buffer[buf + len_test - 1], true, mf.buffer[buf_back + len_test], mf.buffer[buf + len_test]);
                        state_2 = c.updateLiteral(state_2);
                        pos_state_next = (pos_state_next + 1) & co.pos_mask;
                        const next_rep_match_price = cur_and_len_literal_price +
                            rcmod.bit1Price(co.probs.is_match[state_2][pos_state_next]) +
                            rcmod.bit1Price(co.probs.is_rep[state_2]);
                        const offset = cur + len_test + 1 + len_test_2;
                        while (len_end < offset) {
                            len_end += 1;
                            co.opts[len_end].price = rcmod.infinity_price;
                        }
                        cur_and_len_price = next_rep_match_price + co.repPrice(0, len_test_2, state_2, pos_state_next);
                        if (cur_and_len_price < co.opts[offset].price) {
                            co.opts[offset].price = cur_and_len_price;
                            co.opts[offset].pos_prev = cur + len_test + 1;
                            co.opts[offset].back_prev = 0;
                            co.opts[offset].prev_1_is_literal = true;
                            co.opts[offset].prev_2 = true;
                            co.opts[offset].pos_prev_2 = cur;
                            co.opts[offset].back_prev_2 = cur_back + c.reps;
                        }
                    }
                    i += 1;
                    if (i == matches_count) break;
                }
            }
        }
        return len_end;
    }

    fn optimumNormal(co: *Coder, mf: *Mf, back_res: *u32, len_res: *u32, position: u32) void {
        if (co.opts_end_index != co.opts_current_index) {
            len_res.* = co.opts[co.opts_current_index].pos_prev - co.opts_current_index;
            back_res.* = co.opts[co.opts_current_index].back_prev;
            co.opts_current_index = co.opts[co.opts_current_index].pos_prev;
            return;
        }
        if (mf.read_ahead == 0) {
            if (co.match_price_count >= (1 << 7)) co.fillDistPrices();
            if (co.align_price_count >= c.align_size) co.fillAlignPrices();
        }
        var len_end = co.helper1(mf, back_res, len_res, position);
        if (len_end == std.math.maxInt(u32)) return;
        var reps = co.reps;
        var cur: u32 = 1;
        while (cur < len_end) : (cur += 1) {
            co.longest_match_length = mf.find(&co.matches_count, &co.matches);
            if (co.longest_match_length >= mf.nice_len) break;
            len_end = co.helper2(mf, &reps, mf.read_pos - 1, len_end, position + cur, cur, mf.nice_len, @min(mf.avail() + 1, opts_max - 1 - cur));
        }
        co.backward(len_res, back_res, cur);
    }
};
