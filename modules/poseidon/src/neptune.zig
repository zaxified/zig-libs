// SPDX-License-Identifier: MIT
//! Poseidon over the BLS12-381 scalar field with **Filecoin's `neptune`**
//! parameters and hash framing (MIT OR Apache-2.0, see `NOTICE`): the library
//! Filecoin's proofs and Lurk build their Merkle trees, commitments and
//! transcripts on.
//!
//! What neptune does differently from `bls12_381_poseidon.zig` (the authors'
//! `poseidonperm_x5_255_{3,5}`), every point read from its source:
//!
//!  - **State width and round numbers.** `t = arity + 1`; `R_F = 8` and `R_P`
//!    from its port of the authors' `calc_round_numbers.py` (a 256-bit prime,
//!    128-bit security, 7.5 % margin on `R_P`, `R_F + 2`) — `roundNumbers`.
//!    `Strengthened` adds 25 % to `R_P` (rounded up).
//!  - **Constants.** The authors' Grain generator at `n = 255`, but seeded with
//!    S-box tag **1** (their `create_rcs_grain.sage 1 1 255 t R_F R_P p`), so
//!    they are not the `x5_255` constants.
//!  - **MDS.** Not Grain-drawn: the symmetric Cauchy matrix
//!    `M[i][j] = (i + t + j)^-1`.
//!  - **Framing.** One permutation over `[domain_tag] ++ preimage`; the digest
//!    is state element **1** (the first element after the tag).
//!  - **Domain tags** (`HashType`): Merkle tree `2^arity - 1`; constant length
//!    `len * 2^64`; encryption `2^32`; custom `id * 2^40`, `id` in `1..=256`.
//!
//! Not here: neptune's sponge API (simplex/duplex absorb and squeeze, used for
//! inputs longer than the arity) and its GPU / circuit code; see `SPEC.md`.

const std = @import("std");
const bls = @import("bls12_381");
const perm = @import("perm.zig");

pub const Fr = bls.Fr;

/// neptune's `Strength`: `strengthened` raises `R_P` by 25 % against
/// newly-discovered attacks and gives different constants and digests.
pub const Strength = enum { standard, strengthened };

/// Largest arity neptune implements (`impl_arity!`: `U1 ..= U36`; its `Arity::tag`
/// is a `u64` shift). `roundNumbers` itself is checked for widths up to 125.
pub const max_arity = 36;

pub const RoundNumbers = struct { r_f: u10, r_p: u10 };

/// `(R_F, R_P)` for a state width `t`, neptune's `calc_round_numbers(t, true)`:
/// for every even `R_F` and every `R_P` that satisfies the Poseidon paper's
/// security inequalities for a 256-bit prime and 128-bit security, take
/// `R_F + 2` and `ceil(1.075 R_P)`, and keep the cheapest `t R_F + R_P`
/// (ties: fewer full rounds). The inequalities use `f32` as the source does.
pub fn roundNumbers(t: usize) RoundNumbers {
    var rf: usize = 0;
    var rp: usize = 0;
    var min_cost: usize = std.math.maxInt(usize);
    // The source loops `R_F` (even, 2..=1000) outside `R_P` (4..200) and keeps the
    // first cheapest pair. For a fixed `R_P` a larger `R_F` only costs more, so the
    // smallest secure `R_F` of each `R_P` decides: same winner, 200 steps not 100 000
    // (the table test checks every width 2..125 against the script's output).
    var rp_test: usize = 4;
    while (rp_test < 200) : (rp_test += 1) {
        const need = requiredFullRounds(t, rp_test);
        const rf_test: usize = @max(@as(usize, 2), need + (need & 1)); // the next even number
        if (rf_test > 1000) continue;
        const rf_margin = rf_test + 2;
        const rp_margin: usize = @intFromFloat(@ceil(@as(f32, 1.075) * @as(f32, @floatFromInt(rp_test))));
        const cost = t * rf_margin + rp_margin;
        if (cost < min_cost or (cost == min_cost and rf_margin < rf)) {
            rf = rf_margin;
            rp = rp_margin;
            min_cost = cost;
        }
    }
    return .{ .r_f = @intCast(rf), .r_p = @intCast(rp) };
}

/// The least `R_F` the paper's security inequalities (statistical, interpolation
/// and the two Gröbner-basis bounds) allow for `R_P` partial rounds, a 256-bit
/// prime and 128-bit security: `neptune`'s `round_numbers_are_secure` is
/// `rf >= requiredFullRounds`. The arithmetic is `f32`, as in the source.
fn requiredFullRounds(t_: usize, rp_: usize) usize {
    const rp: f32 = @floatFromInt(rp_);
    const t: f32 = @floatFromInt(t_);
    const n: f32 = 256.0;
    const m: f32 = 128.0;
    const rf_stat: f32 = if (m <= (n - 3.0) * (t + 1.0)) 6.0 else 10.0;
    const rf_interp: f32 = @as(f32, 0.43) * m + @log2(t) - rp;
    const rf_grob_1: f32 = @as(f32, 0.21) * n - rp;
    const rf_grob_2: f32 = (@as(f32, 0.14) * n - 1.0 - rp) / (t - 1.0);
    var rf_max: usize = 0;
    for ([_]f32{ rf_stat, rf_interp, rf_grob_1, rf_grob_2 }) |x| {
        const c = @ceil(x);
        // Rust's `as usize` saturates negatives to 0.
        const v: usize = if (c <= 0) 0 else @intFromFloat(c);
        rf_max = @max(rf_max, v);
    }
    return rf_max;
}

/// `R_P` of an arity under a strength.
pub fn partialRounds(arity: usize, strength: Strength) u10 {
    const rp = roundNumbers(arity + 1).r_p;
    return switch (strength) {
        .standard => rp,
        .strengthened => @intFromFloat(@ceil(@as(f64, @floatFromInt(rp)) * 1.25)),
    };
}

/// The domain-separation tag kinds neptune supports for one-permutation hashes.
pub const HashType = union(enum) {
    /// `2^arity - 1`: a full Merkle node (Filecoin's tree hash).
    merkle_tree,
    /// `len * 2^64`, for `len <= arity` inputs, the rest of the state zero.
    constant_length: usize,
    /// `2^32`.
    encryption,
    /// `id * 2^40`, `id` in `1..=256`.
    custom: u16,
};

pub const Error = error{
    /// The preimage length is not the one the hash type needs (`arity` for
    /// `merkle_tree`, `encryption` and `custom`; `len` for `constant_length`).
    InvalidPreimageLength,
    /// `constant_length` longer than the arity needs neptune's sponge (not here),
    /// and a `custom` id outside `1..=256` is neptune's own range error.
    UnsupportedHashType,
};

/// The permutation and hasher for one arity and strength. Build with `init`
/// once (it runs the Grain generator) and share it.
pub fn Hasher(comptime arity: usize, comptime strength: Strength) type {
    if (arity < 1 or arity > max_arity) @compileError("poseidon/neptune: arity must be in 1..=36 (the arities neptune implements)");
    const rn = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk roundNumbers(arity + 1);
    };
    const rp = comptime partialRounds(arity, strength);
    const P = perm.Permutation(.{
        .Fr = Fr,
        .modulus_be = bls.scalar.r_bytes,
        .n = 255,
        .t = arity + 1,
        .r_f = rn.r_f,
        .r_p = rp,
        .sbox_tag = 1,
        .mds = .cauchy_consecutive,
    });
    return struct {
        const Self = @This();

        permutation: P,

        pub const Permutation = P;

        pub fn init() Self {
            return .{ .permutation = P.init() };
        }

        /// The domain tag of a hash type as a field element.
        pub fn domainTag(ht: HashType) Error!Fr {
            return switch (ht) {
                .merkle_tree => fromU128((@as(u128, 1) << arity) - 1),
                .constant_length => |len| blk: {
                    if (len > arity) return error.UnsupportedHashType;
                    break :blk fromU128(@as(u128, len) << 64);
                },
                .encryption => fromU128(@as(u128, 1) << 32),
                .custom => |id| blk: {
                    if (id < 1 or id > 256) return error.UnsupportedHashType;
                    break :blk fromU128(@as(u128, id) << 40);
                },
            };
        }

        /// One permutation over `[tag] ++ preimage ++ zeros`; the digest is
        /// state element 1, as neptune's `Poseidon::hash` returns.
        pub fn hash(self: *const Self, ht: HashType, preimage: []const Fr) Error!Fr {
            const want = switch (ht) {
                .constant_length => |len| len,
                else => arity,
            };
            if (preimage.len != want) return error.InvalidPreimageLength;
            var state: [arity + 1]Fr = @splat(Fr.zero);
            state[0] = try domainTag(ht);
            @memcpy(state[1..][0..preimage.len], preimage);
            return self.permutation.permute(state)[1];
        }

        /// `hash` with `merkle_tree` framing on a fixed-size array.
        pub fn merkle(self: *const Self, inputs: [arity]Fr) Fr {
            return self.hash(.merkle_tree, &inputs) catch unreachable;
        }
    };
}

fn fromU128(v: u128) Fr {
    var be: [32]u8 = @splat(0);
    std.mem.writeInt(u128, be[16..32], v, .big);
    return Fr.fromBytes(be) catch unreachable;
}
