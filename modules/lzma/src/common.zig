// SPDX-License-Identifier: MIT

//! Constants and the probability model shared by the LZMA decoder and
//! encoder (the layout of liblzma's `lzma_common.h`).

const std = @import("std");

pub const prob_bits = 11;
pub const prob_init: u16 = 1 << (prob_bits - 1);
pub const move_bits = 5;
pub const top_value: u32 = 1 << 24;

pub const states = 12;
pub const lit_states = 7;
pub const pos_states_max = 16;
pub const match_len_min = 2;
pub const match_len_max = 273;
pub const len_low_symbols = 8;
pub const len_mid_symbols = 8;
pub const len_high_symbols = 256;
pub const len_symbols = len_low_symbols + len_mid_symbols + len_high_symbols;
pub const dist_states = 4;
pub const dist_slot_bits = 6;
pub const dist_slots = 1 << dist_slot_bits;
pub const dist_model_start = 4;
pub const dist_model_end = 14;
pub const full_distances = 1 << (dist_model_end / 2);
pub const align_bits = 4;
pub const align_size = 1 << align_bits;
pub const reps = 4;
pub const literal_coder_size = 0x300;
/// lc + lp is at most 4 (liblzma's LZMA_LCLP_MAX), pb at most 4.
pub const lclp_max = 4;
pub const pb_max = 4;

/// The distance value that marks the end of the payload.
pub const eopm_distance: u32 = 0xFFFF_FFFF;

pub const State = enum(u8) {
    lit_lit,
    match_lit_lit,
    rep_lit_lit,
    shortrep_lit_lit,
    match_lit,
    rep_lit,
    shortrep_lit,
    lit_match,
    lit_longrep,
    lit_shortrep,
    nonlit_match,
    nonlit_rep,
    _,
};

pub inline fn updateLiteral(s: u8) u8 {
    return if (s <= 3) 0 else if (s <= 9) s - 3 else s - 6;
}
pub inline fn updateMatch(s: u8) u8 {
    return if (s < lit_states) 7 else 10;
}
pub inline fn updateLongRep(s: u8) u8 {
    return if (s < lit_states) 8 else 11;
}
pub inline fn updateShortRep(s: u8) u8 {
    return if (s < lit_states) 9 else 11;
}
pub inline fn isLiteralState(s: u8) bool {
    return s < lit_states;
}

pub inline fn distState(len: u32) u32 {
    return if (len < dist_states + match_len_min) len - match_len_min else dist_states - 1;
}

pub const LenProbs = extern struct {
    choice: u16,
    choice2: u16,
    low: [pos_states_max][len_low_symbols]u16,
    mid: [pos_states_max][len_mid_symbols]u16,
    high: [len_high_symbols]u16,
};

/// The whole model. `literal` holds `0x300 << (lc + lp)` entries in use.
pub const Probs = extern struct {
    is_match: [states][pos_states_max]u16,
    is_rep: [states]u16,
    is_rep0: [states]u16,
    is_rep1: [states]u16,
    is_rep2: [states]u16,
    is_rep0_long: [states][pos_states_max]u16,
    dist_slot: [dist_states][dist_slots]u16,
    pos_special: [full_distances - dist_model_end]u16,
    pos_align: [align_size]u16,
    match_len: LenProbs,
    rep_len: LenProbs,
    literal: [literal_coder_size << lclp_max]u16,

    pub fn reset(p: *Probs, lc: u32, lp: u32) void {
        const n_lit = @as(usize, literal_coder_size) << @intCast(lc + lp);
        // Everything but `literal` is a flat run of u16 at the start.
        const head: *[@offsetOf(Probs, "literal") / 2]u16 = @ptrCast(p);
        @memset(head, prob_init);
        @memset(p.literal[0..n_lit], prob_init);
    }
};

/// lc, lp, pb of an LZMA1 / LZMA2 properties byte.
pub const Lclppb = struct {
    lc: u8,
    lp: u8,
    pb: u8,

    /// `null` when the byte is not a valid properties byte (>= 225) or lc + lp
    /// exceeds 4.
    pub fn decode(byte: u8) ?Lclppb {
        if (byte >= 9 * 5 * 5) return null;
        var d: u8 = byte;
        const lc = d % 9;
        d /= 9;
        const lp = d % 5;
        const pb = d / 5;
        if (lc + lp > lclp_max) return null;
        return .{ .lc = lc, .lp = lp, .pb = pb };
    }

    pub fn encode(p: Lclppb) u8 {
        return (p.pb * 5 + p.lp) * 9 + p.lc;
    }
};
