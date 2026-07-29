// SPDX-License-Identifier: MIT
//! Poseidon over the **BLS12-381 scalar field**, with the Poseidon authors'
//! own published parameter sets `poseidonperm_x5_255_3` and
//! `poseidonperm_x5_255_5`.
//!
//! Deliberately narrower than the BN254 side. Upstream publishes reference
//! `.sage` files *and* test vectors for exactly these two widths
//! (`hadeshash/code/poseidonperm_x5_255_{3,5}.sage`, outputs recorded in
//! `hadeshash/code/test_vectors.txt`); there is no published `R_P` table for
//! other widths over this field and no deployed implementation to be
//! byte-compatible with, so other widths would be unanchored guesses. See
//! `SPEC.md` §"Why BLS12-381 stops at t = 3 and t = 5".
//!
//! The Grain seed width here is `n = 255`, against BN254's 254. That is a
//! *seed* input, not merely a draw width: instantiating this field with
//! `n = 254` would produce a completely different — and completely
//! unanchored — permutation over the same prime.

const std = @import("std");
const bls = @import("bls12_381");
const perm = @import("perm.zig");

pub const Fr = bls.Fr;

pub const N_ROUNDS_F: u10 = 8;

/// The Poseidon permutation over the BLS12-381 scalar field at `t = 3` or
/// `t = 5`. Call `.init()` on the returned type.
///
/// ⚠ The *hash* framing (`hash`/`compress`: state `[0] ++ inputs`, first
/// output element) has **no deployed counterpart on this field** — only the
/// raw permutation is externally anchored. Before interoperating with
/// somebody else's BLS12-381 Poseidon (Filecoin's `neptune`, dusk,
/// arkworks…), check their domain-tag and padding conventions: they differ
/// from each other and from this one.
pub fn Perm(comptime t: u12) type {
    const r_p: u10 = switch (t) {
        3 => 57, // poseidonperm_x5_255_3
        5 => 60, // poseidonperm_x5_255_5
        else => @compileError("poseidon/bls12_381: only t = 3 and t = 5 have published parameters and vectors for this field"),
    };
    return perm.Permutation(.{
        .Fr = Fr,
        .modulus_be = bls.scalar.r_bytes,
        .n = 255,
        .t = t,
        .r_f = N_ROUNDS_F,
        .r_p = r_p,
    });
}

pub fn fromU64(v: u64) Fr {
    var be: [32]u8 = @splat(0);
    std.mem.writeInt(u64, be[24..32], v, .big);
    return Fr.fromBytes(be) catch unreachable;
}
