// SPDX-License-Identifier: MIT

//! The Rescue-Prime Optimized permutation (`rescue_XLIX_permutation` in the
//! reference implementation), parameterised by instance.
//!
//! Seven identical rounds, each **two half-rounds**:
//!
//! ```text
//!   half 1:  state <- MDS * state ;  state += ARK1[r] ;  state <- state^alpha
//!   half 2:  state <- MDS * state ;  state += ARK2[r] ;  state <- state^(1/alpha)
//! ```
//!
//! The asymmetry between the halves is the whole design. Half 1 is cheap to
//! evaluate (`x^7`, 5 multiplies) and expensive to constrain; half 2 is
//! expensive to evaluate (`x^(1/7)`, 72 multiplies) and cheap to constrain,
//! because a verifier checks `y^7 == x` instead of computing the root. A
//! prover pays 12 constraints of degree 7 per round either way while software
//! pays 15.0x more for the second half (measured) — see `README.md` for when
//! that trade is the one you want.
//!
//! **Note the order.** The MDS comes *before* the constants and the S-box.
//! That is RPO's change from the original Rescue-Prime, where the round is
//! `S-box -> MDS -> ARK`, and it is not cosmetic: `xlix.zig` implements the
//! original order and produces a completely different permutation from the
//! same MDS.

const std = @import("std");
const gl = @import("goldilocks.zig");
const params = @import("params.zig");

pub fn Permutation(comptime inst: params.Instance) type {
    return struct {
        pub const instance = inst;
        pub const width = inst.m;
        pub const rate = inst.rate();
        pub const capacity = inst.capacity;
        pub const rounds = params.num_rounds;

        /// A permutation state: `m` field elements.
        pub const State = [inst.m]gl.Fe;

        const mds = params.mdsRow(inst);
        const rc = params.roundConstants(inst);

        /// Round constants for the first half-round of round `r`.
        pub fn ark1(r: usize) *const [inst.m]gl.Fe {
            return @ptrCast(rc[r * 2 * inst.m ..][0..inst.m]);
        }

        /// Round constants for the second half-round of round `r`.
        pub fn ark2(r: usize) *const [inst.m]gl.Fe {
            return @ptrCast(rc[r * 2 * inst.m + inst.m ..][0..inst.m]);
        }

        /// `out[i] = sum_j MDS[(j - i) mod m] * state[j]` — multiplication by
        /// the circulant matrix whose first row is `mdsRow`. (Sage's
        /// `matrix.circulant(v)[i][j] == v[(j - i) mod m]`; getting that index
        /// backwards transposes the matrix and silently yields a different,
        /// still-invertible permutation.)
        ///
        /// The accumulator is a `u128` and reduced once at the end rather than
        /// per term: every MDS entry is small (`< 2^31`), so `m` products stay
        /// below `2^99` and cannot overflow.
        pub fn applyMds(state: *State) void {
            var out: State = undefined;
            for (0..inst.m) |i| {
                var acc: u128 = 0;
                for (0..inst.m) |j| {
                    acc += @as(u128, state[j]) * @as(u128, mds[(j + inst.m - i) % inst.m]);
                }
                out[i] = gl.reduce128(acc);
            }
            state.* = out;
        }

        pub fn applySbox(state: *State) void {
            gl.sboxLayer(inst.m, state);
        }

        pub fn applySboxInv(state: *State) void {
            gl.sboxInvLayer(inst.m, state);
        }

        fn addConstants(state: *State, ark: *const [inst.m]gl.Fe) void {
            for (state, ark) |*s, k| s.* = gl.add(s.*, k);
        }

        /// One RPO round.
        pub fn applyRound(state: *State, r: usize) void {
            applyMds(state);
            addConstants(state, ark1(r));
            applySbox(state);

            applyMds(state);
            addConstants(state, ark2(r));
            applySboxInv(state);
        }

        /// The full 7-round permutation, in place.
        pub fn permute(state: *State) void {
            for (0..rounds) |r| applyRound(state, r);
        }

        /// The inverse permutation. Not used by any hash — a sponge never runs
        /// backwards — but it is the cheapest possible check that the round
        /// function was transcribed correctly in *both* halves, so it earns its
        /// place. Costs the same as `permute` (the halves swap roles).
        pub fn permuteInverse(state: *State) void {
            var r: usize = rounds;
            while (r > 0) {
                r -= 1;
                applySbox(state); // undo x^(1/alpha)
                subConstants(state, ark2(r));
                applyMdsInverse(state);

                applySboxInv(state); // undo x^alpha
                subConstants(state, ark1(r));
                applyMdsInverse(state);
            }
        }

        fn subConstants(state: *State, ark: *const [inst.m]gl.Fe) void {
            for (state, ark) |*s, k| s.* = gl.sub(s.*, k);
        }

        /// Inverse of the circulant MDS, obtained by Gauss-Jordan elimination
        /// at comptime. Only `permuteInverse` and the MDS-invertibility test
        /// use it, so it is computed lazily per instantiation rather than
        /// stored alongside the forward matrix.
        const inv_mds: [inst.m][inst.m]gl.Fe = blk: {
            @setEvalBranchQuota(10_000_000);
            var a: [inst.m][2 * inst.m]gl.Fe = undefined;
            for (0..inst.m) |i| {
                for (0..inst.m) |j| a[i][j] = mds[(j + inst.m - i) % inst.m];
                for (0..inst.m) |j| a[i][inst.m + j] = if (i == j) 1 else 0;
            }
            for (0..inst.m) |col| {
                var piv = col;
                while (a[piv][col] == 0) piv += 1; // MDS: never singular
                const tmp = a[col];
                a[col] = a[piv];
                a[piv] = tmp;
                const inv = gl.pow(a[col][col], gl.P - 2);
                for (0..2 * inst.m) |j| a[col][j] = gl.mul(a[col][j], inv);
                for (0..inst.m) |i| {
                    if (i == col or a[i][col] == 0) continue;
                    const f = a[i][col];
                    for (0..2 * inst.m) |j| {
                        a[i][j] = gl.sub(a[i][j], gl.mul(f, a[col][j]));
                    }
                }
            }
            var out: [inst.m][inst.m]gl.Fe = undefined;
            for (0..inst.m) |i| for (0..inst.m) |j| {
                out[i][j] = a[i][inst.m + j];
            };
            break :blk out;
        };

        fn applyMdsInverse(state: *State) void {
            var out: State = undefined;
            for (0..inst.m) |i| {
                var acc: gl.Fe = 0;
                for (0..inst.m) |j| acc = gl.add(acc, gl.mul(inv_mds[i][j], state[j]));
                out[i] = acc;
            }
            state.* = out;
        }
    };
}

const P128 = Permutation(params.Instance.bits128);
const P160 = Permutation(params.Instance.bits160);

test "MDS is invertible: M * M^-1 = I on every basis vector" {
    inline for (.{ P128, P160 }) |Perm| {
        for (0..Perm.width) |k| {
            var st: Perm.State = @splat(0);
            st[k] = 1;
            Perm.applyMds(&st);
            Perm.applyMdsInverse(&st);
            for (0..Perm.width) |i| {
                try std.testing.expectEqual(@as(gl.Fe, if (i == k) 1 else 0), st[i]);
            }
        }
    }
}

test "permuteInverse undoes permute" {
    inline for (.{ P128, P160 }) |Perm| {
        var prng = std.Random.DefaultPrng.init(0x52_65_73_63_75_65_00_01);
        const rnd = prng.random();
        for (0..24) |_| {
            var st: Perm.State = undefined;
            for (&st) |*s| s.* = gl.fromU64(rnd.int(u64));
            const original = st;
            Perm.permute(&st);
            try std.testing.expect(!std.mem.eql(gl.Fe, &original, &st));
            Perm.permuteInverse(&st);
            try std.testing.expectEqualSlices(gl.Fe, &original, &st);
        }
    }
}

test "round constants are laid out as the spec's flat stream" {
    // rc[i*2m .. +m] is half one; rc[i*2m+m .. +m] is half two. Reading the
    // stream as "all ARK1 first, then all ARK2" is a classic transcription
    // error and would pass every structural test.
    const rc = params.roundConstants(params.Instance.bits128);
    for (0..params.num_rounds) |r| {
        try std.testing.expectEqualSlices(gl.Fe, rc[r * 24 ..][0..12], P128.ark1(r));
        try std.testing.expectEqualSlices(gl.Fe, rc[r * 24 + 12 ..][0..12], P128.ark2(r));
    }
}
