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
//! `permute` runs the **optimised equivalent** of this schedule (the Poseidon
//! paper's appendix, as neptune does): partial-round constants folded forward
//! through the MDS matrix so each partial round adds one scalar, and the
//! partial rounds' `t x t` products replaced by sparse ones (first row and
//! column dense, the rest the identity) plus one dense pre-matrix, `O(t)` per
//! partial round. It computes the same function, bit for bit; `permutePlain`
//! is the schedule above, kept as the differential. See `SPEC.md`
//! ("Optimised partial rounds").
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
        /// Optimised-partial-round tables (derived from the two above in
        /// `initChecked`). `pre_matrix` is `M^ R_P` of the `(t-1)x(t-1)` block
        /// of the MDS matrix; `sparse_row[p]` / `sparse_col[p]` are the first
        /// row (past the corner) and column of partial round `p`'s sparse
        /// matrix; `partial_c[p]` is its folded scalar constant; `tail_c` is
        /// the constant vector of the first round after the partial rounds
        /// with the forwarded remainder added.
        pre_matrix: [cfg.t - 1][cfg.t - 1]Fr,
        sparse_row: [cfg.r_p][cfg.t - 1]Fr,
        sparse_col: [cfg.r_p][cfg.t - 1]Fr,
        partial_c: [cfg.r_p]Fr,
        tail_c: [cfg.t]Fr,

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
        ///
        /// Infallible **for a parameter set that produces one**, which is every
        /// set this module exposes: `grain.derive`'s error cases are a
        /// degenerate `(n, t, R_F, R_P)` whose MDS candidates keep getting
        /// rejected, and they are unreachable for `bn254.Perm`/`bls12_381.Perm`
        /// — `constants_test.zig` derives all 18 of them. Use `initChecked` if
        /// you are driving `Permutation` from a `Config` of your own.
        pub fn init() Self {
            return initChecked() catch |err|
                std.debug.panic("poseidon: parameter derivation failed: {s}", .{@errorName(err)});
        }

        /// `init` with the derivation's error surfaced rather than panicked on.
        pub fn initChecked() grain.Error!Self {
            const tables = try grain.derive(cfg);
            var self: Self = undefined;
            self.round_constants = tables.round_constants;
            self.mds = tables.mds;
            try self.buildSparse();
            return self;
        }

        const nh = t - 1;
        const half_f = r_f / 2;
        const tail_n = r_f - half_f;

        /// `out = a * b` for `nh x nh` matrices.
        fn matMulHat(a: *const [nh][nh]Fr, b: *const [nh][nh]Fr) [nh][nh]Fr {
            var out: [nh][nh]Fr = undefined;
            for (0..nh) |i| {
                for (0..nh) |j| {
                    var acc = Fr.zero;
                    for (0..nh) |k| acc = acc.add(a[i][k].mul(b[k][j]));
                    out[i][j] = acc;
                }
            }
            return out;
        }

        /// Gauss-Jordan inverse of an `nh x nh` matrix. Public data only (the
        /// pivot search branches on values), run once per `init`.
        fn invertHat(m: *const [nh][nh]Fr) grain.Error![nh][nh]Fr {
            var a = m.*;
            var inv: [nh][nh]Fr = undefined;
            for (0..nh) |i| for (0..nh) |j| {
                inv[i][j] = if (i == j) Fr.one else Fr.zero;
            };
            for (0..nh) |col| {
                var piv = col;
                while (piv < nh and a[piv][col].isZero()) piv += 1;
                if (piv == nh) return error.NotInvertible;
                std.mem.swap([nh]Fr, &a[col], &a[piv]);
                std.mem.swap([nh]Fr, &inv[col], &inv[piv]);
                const pinv = try a[col][col].inv();
                for (0..nh) |j| {
                    a[col][j] = a[col][j].mul(pinv);
                    inv[col][j] = inv[col][j].mul(pinv);
                }
                for (0..nh) |i| {
                    if (i == col or a[i][col].isZero()) continue;
                    const f = a[i][col];
                    for (0..nh) |j| {
                        a[i][j] = a[i][j].sub(f.mul(a[col][j]));
                        inv[i][j] = inv[i][j].sub(f.mul(inv[col][j]));
                    }
                }
            }
            return inv;
        }

        /// The paper's equivalent partial-round form (neptune's
        /// `preprocessing.rs` / `matrix.rs`). With `M = [[m00, w^T], [v, H]]`
        /// and `S0` the first-element S-box, `M = Sp_k * diag(1, H^k)` for the
        /// sparse `Sp_k = [[m00, w^T H^-k], [H^(k-1) v, I]]`, and `diag(1, .)`
        /// commutes with `S0` and with adding a constant to element 0, so the
        /// `R_P` rounds `M S0 (. + a_p e0)` become one pre-matrix `diag(1, H^R_P)`
        /// followed by `R_P` sparse rounds. The constants' elements 1.. are
        /// carried forward (`a_(p+1) = c_(p+1) + M * rest(a_p)`) until the first
        /// full round after the partial section.
        fn buildSparse(self: *Self) grain.Error!void {
            if (r_p == 0) return;
            var h: [nh][nh]Fr = undefined;
            var v: [nh]Fr = undefined;
            var w: [nh]Fr = undefined;
            for (0..nh) |i| {
                v[i] = self.mds[i + 1][0];
                w[i] = self.mds[0][i + 1];
                for (0..nh) |j| h[i][j] = self.mds[i + 1][j + 1];
            }
            const hinv = try invertHat(&h);

            // Sparse matrix k = 1..R_P belongs to partial round p = R_P - k.
            var col = v; // H^(k-1) v
            var row = w; // w^T H^-k, after the first step below
            for (1..r_p + 1) |k| {
                var nrow: [nh]Fr = undefined;
                for (0..nh) |j| {
                    var acc = Fr.zero;
                    for (0..nh) |i| acc = acc.add(row[i].mul(hinv[i][j]));
                    nrow[j] = acc;
                }
                row = nrow;
                self.sparse_row[r_p - k] = row;
                self.sparse_col[r_p - k] = col;
                var ncol: [nh]Fr = undefined;
                for (0..nh) |i| {
                    var acc = Fr.zero;
                    for (0..nh) |j| acc = acc.add(h[i][j].mul(col[j]));
                    ncol[i] = acc;
                }
                col = ncol;
            }

            // H^R_P by repeated squaring.
            var result: [nh][nh]Fr = undefined;
            for (0..nh) |i| for (0..nh) |j| {
                result[i][j] = if (i == j) Fr.one else Fr.zero;
            };
            var base = h;
            var e: usize = r_p;
            while (e > 0) {
                if (e & 1 == 1) result = matMulHat(&result, &base);
                e >>= 1;
                if (e > 0) base = matMulHat(&base, &base);
            }
            self.pre_matrix = result;

            // Constants.
            var a: [t]Fr = self.round_constants[half_f * t ..][0..t].*;
            for (0..r_p) |p| {
                self.partial_c[p] = a[0];
                var next: [t]Fr = @splat(Fr.zero);
                if (half_f + p + 1 < r_f + r_p) next = self.round_constants[(half_f + p + 1) * t ..][0..t].*;
                for (0..t) |i| {
                    var acc = next[i];
                    for (1..t) |j| acc = acc.add(self.mds[i][j].mul(a[j]));
                    next[i] = acc;
                }
                a = next;
            }
            self.tail_c = a;
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
        /// hash framing lives on top of it. The optimised schedule: output
        /// identical to `permutePlain`.
        pub fn permute(self: *const Self, input: [t]Fr) [t]Fr {
            if (r_p == 0) return self.permutePlain(input);
            var state = input;
            var k: usize = 0;
            for (0..half_f) |_| {
                state = self.fullRound(state, self.round_constants[k..][0..t]);
                k += t;
            }
            // Partial rounds: dense pre-matrix on elements 1.., then R_P sparse rounds.
            var rest: [nh]Fr = undefined;
            for (0..nh) |i| {
                var acc = Fr.zero;
                for (0..nh) |j| acc = acc.add(self.pre_matrix[i][j].mul(state[j + 1]));
                rest[i] = acc;
            }
            var s0 = state[0];
            const m00 = self.mds[0][0];
            for (0..r_p) |p| {
                const x0 = sbox(s0.add(self.partial_c[p]));
                var acc = m00.mul(x0);
                for (0..nh) |j| {
                    acc = acc.add(self.sparse_row[p][j].mul(rest[j]));
                    rest[j] = rest[j].add(self.sparse_col[p][j].mul(x0));
                }
                s0 = acc;
            }
            state[0] = s0;
            @memcpy(state[1..], &rest);
            k += r_p * t;
            if (tail_n == 0) {
                for (0..t) |i| state[i] = state[i].add(self.tail_c[i]);
                return state;
            }
            state = self.fullRound(state, &self.tail_c);
            k += t;
            for (1..tail_n) |_| {
                state = self.fullRound(state, self.round_constants[k..][0..t]);
                k += t;
            }
            return state;
        }

        fn fullRound(self: *const Self, in: [t]Fr, c: *const [t]Fr) [t]Fr {
            var state = in;
            for (0..t) |i| state[i] = sbox(state[i].add(c[i]));
            return self.mix(state);
        }

        /// The textbook schedule from the header comment (`O(t^2)` partial
        /// rounds). The reference `permute` is differentially tested against;
        /// a caller has no reason to prefer it.
        pub fn permutePlain(self: *const Self, input: [t]Fr) [t]Fr {
            var state = input;
            var k: usize = 0;
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

test "mutation 2026-11-25: invertHat pivots past a zero entry and refuses a singular matrix" {
    const small_field = @import("small_field.zig");
    const F = small_field.SmallField(101);
    const P = Permutation(.{ .Fr = F, .modulus_be = F.modulus_be, .n = 7, .t = 3, .r_f = 2, .r_p = 1, .mds = .cauchy_consecutive });
    const small = struct {
        fn f(v: u8) F {
            var be: [32]u8 = @splat(0);
            be[31] = v;
            return F.fromBytes(be) catch unreachable;
        }
    }.f;
    const id: [2][2]F = .{ .{ small(1), small(0) }, .{ small(0), small(1) } };
    // a zero on the diagonal: the pivot row is found below and swapped in
    const m: [2][2]F = .{ .{ small(0), small(2) }, .{ small(3), small(0) } };
    const inv = try P.invertHat(&m);
    const prod = P.matMulHat(&m, &inv);
    for (0..2) |i| for (0..2) |j| try std.testing.expect(prod[i][j].eql(id[i][j]));
    // no nonzero pivot in the second column
    const s: [2][2]F = .{ .{ small(0), small(0) }, .{ small(1), small(1) } };
    try std.testing.expectError(error.NotInvertible, P.invertHat(&s));
}
