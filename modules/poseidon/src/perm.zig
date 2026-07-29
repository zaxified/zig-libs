// SPDX-License-Identifier: MIT
//! The HADES permutation itself, generic over a field and a parameter set.
//!
//! Short by design — the hard part of Poseidon is upstream, in `grain.zig`,
//! deciding *which* numbers go in. What is left is:
//!
//! ```
//! for round in 0 .. R_F + R_P:
//!     state[i] += C[round*t + i]      for all i        (ARK, every round)
//!     state[i]  = state[i]^alpha      for all i        if full round
//!     state[0]  = state[0]^alpha                       if partial round
//!     state     = M * state                            (MIX)
//! ```
//!
//! with `R_F/2` full rounds at the front, `R_P` partial rounds in the middle,
//! and `R_F/2` full rounds at the back. Three details are load-bearing, and
//! they are exactly the ones a wrong implementation still round-trips through:
//!
//!  - **Round constants are added in every round, to every state element**,
//!    partial rounds included. Only the S-box is partial.
//!  - **A partial round applies the S-box to `state[0]`**. Applying it to the
//!    last element instead, or to all of them, still gives a deterministic
//!    hash — one that simply is not Poseidon.
//!  - **The last round ends with a MIX.** There is no truncated final round.
//!
//! Linear-layer convention: `new[i] = Σ_j M[i][j] * old[j]`, i.e. the
//! reference script's `MDS_matrix_field * vector(state_words)`. See `SPEC.md`
//! §"Divergences" for the transposed convention circom's `Mix` template uses
//! and why it does not change the output.

const std = @import("std");
const grain = @import("grain.zig");

pub const Config = grain.Config;

/// A Poseidon permutation instance: the derived tables plus the operations
/// over them.
///
/// The tables are built by `init()` at **run time** (see `grain.derive` for
/// the measured reason). `init()` is an ordinary function, so
/// `const P = comptime Perm.init();` also works if a caller would rather pay
/// seconds of compile time than microseconds of startup — but the default,
/// and what the tests do, is one `init()` per program.
pub fn Permutation(comptime cfg: Config) type {
    return struct {
        const Self = @This();

        round_constants: [cfg.numConstants()]Fr,
        mds: [cfg.t][cfg.t]Fr,

        pub const Fr = cfg.Fr;
        pub const t = cfg.t;
        pub const r_f = cfg.r_f;
        pub const r_p = cfg.r_p;
        /// S-box exponent. 5 for every parameter set this module ships:
        /// `alpha` must be coprime to `p-1`, and for both BN254's and
        /// BLS12-381's scalar fields 3 divides `p-1` while 5 does not.
        pub const alpha = 5;
        pub const config = cfg;

        /// Derives the round constants and MDS matrix from the Grain LFSR.
        /// Deterministic — no entropy, no allocation, no I/O.
        pub fn init() Self {
            const tables = grain.derive(cfg);
            return .{ .round_constants = tables.round_constants, .mds = tables.mds };
        }

        /// `x^5`, as two squarings and a multiply.
        inline fn sbox(x: Fr) Fr {
            const x2 = x.square();
            return x2.square().mul(x);
        }

        fn mix(self: *const Self, state: [t]Fr) [t]Fr {
            var out: [t]Fr = undefined;
            for (0..t) |i| {
                var acc = Fr.zero;
                for (0..t) |j| acc = acc.add(self.mds[i][j].mul(state[j]));
                out[i] = acc;
            }
            return out;
        }

        /// The permutation. Takes and returns the full `t`-element state; the
        /// hash framing lives on top of it.
        pub fn permute(self: *const Self, input: [t]Fr) [t]Fr {
            var state = input;
            var k: usize = 0;
            const half_f = r_f / 2;
            for (0..r_f + r_p) |round| {
                for (0..t) |i| {
                    state[i] = state[i].add(self.round_constants[k]);
                    k += 1;
                }
                if (round < half_f or round >= half_f + r_p) {
                    for (0..t) |i| state[i] = sbox(state[i]);
                } else {
                    state[0] = sbox(state[0]);
                }
                state = self.mix(state);
            }
            return state;
        }

        /// The circomlib hash framing: state = `[initial_state] ++ inputs`,
        /// one permutation, first `n_out` elements out. `initial_state` is
        /// circomlib's `PoseidonEx.initialState`, zero for the plain
        /// `Poseidon(nInputs)` circuit.
        ///
        /// No padding, no length encoding — the arity is fixed by the type.
        /// That is what a circuit wants, and it is why this is not a
        /// variable-length hash; see `SPEC.md`.
        pub fn hashN(
            self: *const Self,
            comptime n_out: usize,
            initial_state: Fr,
            inputs: [t - 1]Fr,
        ) [n_out]Fr {
            comptime std.debug.assert(n_out >= 1 and n_out <= t);
            var state: [t]Fr = undefined;
            state[0] = initial_state;
            @memcpy(state[1..], &inputs);
            const out = self.permute(state);
            return out[0..n_out].*;
        }

        /// `hashN` with the usual defaults: zero initial state, one output.
        pub fn hash(self: *const Self, inputs: [t - 1]Fr) Fr {
            return self.hashN(1, Fr.zero, inputs)[0];
        }

        /// 2-to-1 compression — the Merkle-tree node function, and the reason
        /// this module exists. Only meaningful at `t = 3`.
        pub fn compress(self: *const Self, left: Fr, right: Fr) Fr {
            if (t != 3) @compileError("poseidon: compress is the t = 3 (2-to-1) instance; use hash for other widths");
            return self.hash(.{ left, right });
        }
    };
}
