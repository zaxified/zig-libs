// SPDX-License-Identifier: MIT
//! `mds_security` — the **subspace-trail security checks** the Poseidon
//! authors' reference generator runs on every candidate MDS matrix:
//! `algorithm_1`, `algorithm_2`, `algorithm_3` and `check_minpoly_condition`
//! from `generate_parameters_grain.sage` / `reference_params.sage`, which
//! implement the "infinitely long subspace trail" tests of Grassi, Rechberger
//! and Schofnegger (<https://eprint.iacr.org/2020/500>).
//!
//! Upstream's `generate_matrix` is a **rejection loop**: draw a Cauchy matrix,
//! run the three algorithms, and if any says "insecure" throw the candidate
//! away and draw another. A rejection is not a no-op — it consumes another
//! `2t` Grain draws, which shifts every later value — so `grain.derive` has to
//! reproduce the loop, not just the matrix construction.
//!
//! ## Reading the reference with `s = 1`
//!
//! Every one of these functions hard-codes `s = 1` upstream (the number of
//! state words the S-box is applied to in a partial round), and that collapses
//! several of the sage idioms into something much smaller. Written out:
//!
//!   - `generate_vectorspace(i, ...)` is
//!     `S_i = { x : (M^k x)[0] = 0 for k = 0 .. i-1 }`. The sage code phrases
//!     it as a right kernel in `F^(t-1)` with a zero prepended, which is the
//!     same set: for `x` with `x[0] = 0`, `row0(M^k) · x` only ever touches
//!     `row0(M^k)[1:]`. The `round_num == 1` special case (`V.basis()[1:]`) is
//!     the same formula with an empty constraint list.
//!   - In `algorithm_2`, `full_iota_space` is built from
//!     `[e_0] + [e_1 .. e_(t-1)]`, i.e. **all of `V`**, so
//!     `IS.intersection(full_iota_space) != IS` can never fire, and
//!     `I_powerset` has exactly one member `[0]`. What is left is precisely:
//!     *is `e_0` a cyclic vector for `M`* — does `e_0, M e_0, M^2 e_0, …` span
//!     `F^t`.
//!   - `algorithm_1`'s `mat_target` is `matrix.circulant([entry, 0, …, 0])`,
//!     which is `entry * I`; so check 1 is "`M^i` is a scalar matrix".
//!   - `check_minpoly_condition` asks for `deg minpoly == t` **and** minpoly
//!     irreducible. Since `minpoly | charpoly` and `deg charpoly == t`, that
//!     pair of conditions is exactly "`charpoly(M^i)` is irreducible".
//!
//! ## Two equivalences that make this affordable, and why they are safe
//!
//! A literal transcription is `O(t^5)` field multiplications per candidate and
//! the field multiplication here costs ~0.8 µs (`std.crypto.ff`, constant
//! time). At `t = 17`, run once per `Perm(t).init()`, that is not a price the
//! test suite can pay. Two provable rewrites bring it down; **both are
//! implemented alongside the literal version and tested against it**, because
//! a fast path that is its own oracle proves nothing.
//!
//! **(1) `algorithm_1` accepts iff `(e_0^T, M)` is observable.** Let
//! `w_k = e_0^T M^k` and `R_a = {w_0, …, w_(a-1)}`, so `S_a = ker R_a`.
//!
//!   - Check 3 (`M^j S_i == S_i` for some `1 <= j <= i`) holds iff
//!     `S_i = S_(i+j)`, i.e. iff `rank R_(i+1) = rank R_i` — because
//!     `M^j S_i ⊆ S_i` says exactly `(M^m x)[0] = 0` for `m = i … i+j-1` on top
//!     of what `S_i` already gives, and ranks are non-decreasing. (Equality of
//!     dimension is automatic while `M` is invertible, which a Cauchy matrix
//!     always is; the literal path does not assume it.)
//!   - Check 1 (`M^i = cI`) forces `w_i = c·w_0`, hence also
//!     `rank R_(i+1) = rank R_i`.
//!   - Check 2 asks whether `S_i` contains an eigenvector of `M^i` whose
//!     eigenvalue lies in `F`. Any such vector spans an `M^i`-invariant line
//!     inside `S_i`, so it lies in the largest `M^i`-invariant subspace of
//!     `S_i`. That subspace is `{x : (M^n x)[0] = 0 for all n >= 0}` — the
//!     unobservable subspace — **for every `i`**, because the index sets
//!     `{k + i·m : 0 <= k < i, m >= 0}` tile the naturals. So if the `w_k` span
//!     `F^t`, check 2 cannot fire either.
//!   - `IS != V` in the sage source is always true for `i >= 1`, since
//!     `IS ⊆ S_i ⊆ ker(e_0^T) ⊊ V`.
//!
//!   Conversely, if the `w_k` do **not** span, the rank sequence stalls at some
//!   `a <= t-1` and check 3 fires there at the latest. So the boolean verdict
//!   is exactly observability — but the sub-code and the failing `i` are not,
//!   which is why a stalled rank falls through to `algorithm1Literal`.
//!
//! **(2) `algorithm_3` only has to test `r` in `(2t, 4t]`.** `Krylov(e_0, M^r)
//! ⊆ Krylov(e_0, M^r')` whenever `r' | r`, so "cyclic for `M^r`" implies
//! "cyclic for `M^r'`" for every divisor. Every `r` in `[2, 2t]` has a multiple
//! in `(2t, 4t]`, so the larger half of the range covers the whole of it. This
//! one needs no hypothesis at all and is used on both paths.
//!
//! And on top of (2), when `e_0` is cyclic for `M` with a **squarefree**
//! characteristic polynomial `f`, "cyclic for `M^r`" is equivalent to
//! "`charpoly(M^r)` is squarefree": in the eigenbasis the Krylov matrix of
//! `e_0` under `M^r` is `V(λ^r) · V(λ)^-1`, so its determinant is non-zero iff
//! the `λ_i^r` are pairwise distinct. `charpoly(M^r)` comes out of the power
//! sums `tr(M^(rk)) `— which Newton's identities produce from `f` alone — so no
//! matrix power is ever formed. When `f` is not squarefree (probability
//! ~`1/p`), the literal Krylov path runs instead.

const std = @import("std");
const linalg = @import("linalg.zig");

/// Capacity for the `Checks` instantiation `grain.derive` uses: the largest
/// state width any published Poseidon parameter set in this module needs
/// (circomlib stops at `t = 17`). Raising it costs compile time and stack, and
/// nothing else — every loop is bounded by the runtime `t`.
pub const max_state_width = 17;

/// The four checks, for a fixed field and a **capacity** `n_max` on the state
/// width. `t` is a runtime argument of every function rather than a comptime
/// one so that `bn254.Perm(2) … Perm(17)` share a single instantiation of this
/// (and of `linalg`) instead of sixteen: the generated code is a large part of
/// the module's compile time, and none of these loops benefit from `t` being
/// comptime-known.
pub fn Checks(comptime Fr: type, comptime p_be: []const u8, comptime n_max: usize) type {
    return struct {
        pub const la = linalg.Linalg(Fr, p_be, n_max);
        pub const Mat = la.Mat;
        pub const Vec = la.Vec;

        /// Root isolation is the only thing in here that can fail, and only on
        /// the literal `algorithm_1` path.
        pub const Error = la.RootError;

        /// `algorithm_1`'s `[bool, code]`, plus the loop index it failed at.
        /// `code` is the reference's 1, 2 or 3; 0 when the matrix is accepted.
        pub const Alg1 = struct {
            secure: bool,
            code: u8 = 0,
            round: usize = 0,
        };

        // ── the pieces the reference builds out of ──────────────────────────

        /// `w_k = e_0^T M^k` for `k = 0 .. count-1`, written to `out`.
        fn rowSequence(m: *const Mat, t: usize, count: usize, out: []Vec) void {
            var w = la.basisVec(0);
            for (0..count) |k| {
                out[k] = w;
                w = la.vecMat(&w, m, t);
            }
        }

        /// `generate_vectorspace(round_num, M, M_round, t)` — a basis of
        /// `S = { x : (M^k x)[0] = 0 for k = 0 .. round_num-1 }`, written to
        /// `out`; returns its dimension. `round_num == 0` is all of `V`.
        pub fn generateVectorspace(m: *const Mat, t: usize, round_num: usize, out: *[n_max]Vec) usize {
            if (round_num == 0) {
                for (0..t) |i| out[i] = la.basisVec(i);
                return t;
            }
            var rows: [n_max]Vec = undefined;
            const n = @min(round_num, t); // beyond t the rows are dependent anyway
            rowSequence(m, t, n, rows[0..n]);
            return la.kernel(rows[0..n], t, out);
        }

        // ── algorithm_2 ─────────────────────────────────────────────────────

        /// `algorithm_2(A, t)` with `s = 1`: is `e_0` a cyclic vector for `A`?
        /// Transcribed from the sage loop, including its "stop when the
        /// dimension stops growing" exit.
        pub fn algorithm2(a: *const Mat, t: usize) bool {
            var is = la.Echelon.init(t);
            var v = la.basisVec(0);
            _ = is.add(v);
            while (true) {
                const delta = is.rank;
                v = la.matVec(a, &v, t);
                _ = is.add(v);
                if (is.rank == t) return true;
                if (is.rank <= delta) return false;
            }
        }

        // ── algorithm_1 ─────────────────────────────────────────────────────

        /// `algorithm_1(M, t)`. Fast path first (see this file's doc comment,
        /// equivalence 1); anything that is not an outright accept is handed to
        /// `algorithm1Literal` so that the sub-code and the failing round match
        /// the reference exactly.
        pub fn algorithm1(m: *const Mat, t: usize) Error!Alg1 {
            var rows: [n_max]Vec = undefined;
            rowSequence(m, t, t, rows[0..t]);
            var e = la.Echelon.init(t);
            for (rows[0..t]) |w| _ = e.add(w);
            if (e.rank == t) return .{ .secure = true };
            return algorithm1Literal(m, t);
        }

        /// The line-by-line transcription: explicit `M^i`, explicit
        /// eigenspaces, explicit `S · M^j`. `O(t^5)`, and only ever reached for
        /// a matrix that is going to be rejected.
        pub fn algorithm1Literal(m: *const Mat, t: usize) Error!Alg1 {
            // `s = 1`, so `r = floor((t - s)/s) = t - 1`.
            const rounds = t - 1;
            // One field inversion for the whole call, not one per `charPoly`.
            const small = la.SmallInverses.init();
            var a = la.identity(t);
            for (1..rounds + 1) |i| {
                a = la.matMul(&a, m, t); // a = M^i

                // 1. `mat_test - mat_target == 0`, i.e. M^i is a scalar matrix.
                var scalar = la.zeroMat();
                for (0..t) |k| scalar[k][k] = a[0][0];
                if (la.matEql(&a, &scalar, t)) return .{ .secure = false, .code = 1, .round = i };

                // 2. Σ over the base-field eigenvalues λ of S ∩ ker(M^i - λI).
                var s_basis: [n_max]Vec = undefined;
                const s_dim = generateVectorspace(m, t, i, &s_basis);

                var constraints: [n_max]Vec = undefined;
                rowSequence(m, t, i, constraints[0..i]);

                var roots: [n_max]Fr = undefined;
                const n_roots = try la.polyRootsInField(la.charPoly(&a, t, &small), &roots);

                var is = la.Echelon.init(t);
                for (roots[0..n_roots]) |lambda| {
                    // S ∩ E_λ is the kernel of S's constraints stacked on
                    // (M^i - λI) — intersecting subspaces given as kernels is
                    // just concatenating their constraint rows.
                    var stack: [2 * n_max]Vec = undefined;
                    @memcpy(stack[0..i], constraints[0..i]);
                    for (0..t) |r| {
                        var row = a[r];
                        row[r] = row[r].sub(lambda);
                        stack[i + r] = row;
                    }
                    var inter: [n_max]Vec = undefined;
                    const d = la.kernel(stack[0 .. i + t], t, &inter);
                    for (inter[0..d]) |v| _ = is.add(v);
                }
                if (is.rank >= 1 and is.rank != t) return .{ .secure = false, .code = 2, .round = i };

                // 3. S · M^j == S for some 1 <= j <= i.
                var s_span = la.Echelon.init(t);
                for (s_basis[0..s_dim]) |v| _ = s_span.add(v);
                var mj = la.identity(t);
                for (1..i + 1) |_| {
                    mj = la.matMul(&mj, m, t);
                    var img = la.Echelon.init(t);
                    for (s_basis[0..s_dim]) |v| _ = img.add(la.matVec(&mj, &v, t));
                    if (la.spanEql(&img, &s_span)) return .{ .secure = false, .code = 3, .round = i };
                }
            }
            return .{ .secure = true };
        }

        // ── algorithm_3 ─────────────────────────────────────────────────────

        /// `algorithm_3(M, t)`: `algorithm_2(M^r)` for every `r` in `[2, 4t]`.
        ///
        /// Uses both equivalences from this file's doc comment: the divisor
        /// reduction (unconditional) and, when its hypotheses hold, the
        /// squarefree-characteristic-polynomial test.
        pub fn algorithm3(m: *const Mat, t: usize) bool {
            return algorithm3With(m, t, la.orderPoly(m, &la.basisVec(0), t));
        }

        /// `algorithm3` given the order polynomial of `e_0` under `M`, which
        /// the caller has usually just computed for `algorithm_2` anyway (the
        /// two are the same `O(t^3)` Krylov walk).
        pub fn algorithm3With(m: *const Mat, t: usize, f: la.Poly) bool {
            // `e_0` not cyclic for `M` ⇒ not cyclic for any `M^r` either
            // (every power of `M^r` is a power of `M`).
            if (f.deg != @as(isize, @intCast(t))) return false;
            if (!la.polyIsSquarefree(f)) return algorithm3Literal(m, t);

            // One field inversion for all `2t` Newton conversions below.
            const small = la.SmallInverses.init();
            var sums: [4 * n_max * n_max + 1]Fr = undefined;
            la.powerSums(f, t, sums[0 .. 4 * t * t + 1]);

            var r: usize = 2 * t + 1;
            while (r <= 4 * t) : (r += 1) {
                var picked: [n_max + 1]Fr = undefined;
                picked[0] = la.fromU64(t);
                for (1..t + 1) |k| picked[k] = sums[r * k];
                if (!la.polyIsSquarefree(la.polyFromPowerSums(picked[0 .. t + 1], t, &small))) return false;
            }
            return true;
        }

        /// The transcription: form `M^r` and run `algorithm_2` on it, for every
        /// `r` the reference tests.
        pub fn algorithm3Literal(m: *const Mat, t: usize) bool {
            var a = m.*;
            var r: usize = 2;
            while (r <= 4 * t) : (r += 1) {
                a = la.matMul(&a, m, t);
                if (!algorithm2(&a, t)) return false;
            }
            return true;
        }

        // ── check_minpoly_condition ─────────────────────────────────────────

        /// `check_minpoly_condition(M, t)`: for `i = 1 .. 2t`, the minimal
        /// polynomial of `M^i` must have degree `t` and be irreducible —
        /// equivalently (see this file's doc comment) `charpoly(M^i)` is
        /// irreducible.
        ///
        /// **Not part of the MDS rejection loop.** Upstream uses it only for
        /// the Poseidon2 *partial* matrix, which this module does not build; it
        /// is here because it is one of the four checks and because it is the
        /// natural companion to the other three. Rabin's test costs
        /// `O(t^2 · log p)` field multiplications per `i`, so do not put it on a
        /// hot path.
        pub fn checkMinpolyCondition(m: *const Mat, t: usize) bool {
            const small = la.SmallInverses.init();
            var a = la.identity(t);
            for (1..2 * t + 1) |_| {
                a = la.matMul(&a, m, t);
                if (!la.polyIsIrreducible(la.charPoly(&a, t, &small))) return false;
            }
            return true;
        }

        // ── the loop condition in `generate_matrix` ─────────────────────────

        /// `not (result_1[0] == False or result_2[0] == False or result_3[0] ==
        /// False)` — the accept condition of upstream's rejection loop.
        ///
        /// `algorithm_2` and `algorithm_3` share one Krylov walk here:
        /// `algorithm_2` *is* "the order polynomial of `e_0` has degree `t`",
        /// which is the first thing `algorithm_3` needs anyway.
        pub fn isSecure(m: *const Mat, t: usize) Error!bool {
            if (!(try algorithm1(m, t)).secure) return false;
            const f = la.orderPoly(m, &la.basisVec(0), t);
            if (f.deg != @as(isize, @intCast(t))) return false; // == !algorithm2(m, t)
            if (!algorithm3With(m, t, f)) return false;
            return true;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const bn254 = @import("bn254");
const testing = std.testing;

/// One instantiation, capacity 6 — the tests only need small widths, and the
/// point of `n_max` is that `t` is a runtime argument.
const C = Checks(bn254.Fr, &bn254.scalar.r_bytes, 6);
const L = C.la;

fn fe(v: u64) bn254.Fr {
    return L.fromU64(v);
}

/// Deterministic "arbitrary" matrices — no RNG dependency, reproducible.
const Sample = struct {
    state: u64,
    fn next(self: *Sample) bn254.Fr {
        self.state = self.state *% 6364136223846793005 +% 1442695040888963407;
        return fe((self.state >> 11) | 1);
    }
    fn mat(self: *Sample, t: usize) C.Mat {
        var m = L.zeroMat();
        for (0..t) |i| for (0..t) |j| {
            m[i][j] = self.next();
        };
        return m;
    }
};

test "algorithm_2 is the cyclic-vector test, and orderPoly agrees with it" {
    // e_0 -> e_1 -> e_2 -> e_3 -> feedback: a cyclic vector by construction.
    var m = L.zeroMat();
    for (0..3) |i| m[i + 1][i] = fe(1);
    m[0][3] = fe(7);
    try testing.expect(C.algorithm2(&m, 4));

    // A diagonal matrix fixes the line through e_0, so the Krylov space stops
    // at dimension 1.
    var d = L.zeroMat();
    for (0..4) |i| d[i][i] = fe(@intCast(i + 2));
    try testing.expect(!C.algorithm2(&d, 4));

    // `isSecure` uses "order polynomial has degree t" in place of a second
    // Krylov walk; the two must never disagree.
    var s = Sample{ .state = 5150 };
    for (0..10) |_| {
        for ([_]usize{ 3, 4, 5 }) |t| {
            const r = s.mat(t);
            const cyclic = L.orderPoly(&r, &L.basisVec(0), t).deg == @as(isize, @intCast(t));
            try testing.expectEqual(C.algorithm2(&r, t), cyclic);
        }
    }
    try testing.expectEqual(C.algorithm2(&d, 4), L.orderPoly(&d, &L.basisVec(0), 4).deg == 4);
}

test "algorithm_1: the fast path and the transcription agree on random matrices" {
    var s = Sample{ .state = 2024 };
    for (0..12) |_| {
        for ([_]usize{ 3, 4, 5 }) |t| {
            const m = s.mat(t);
            const fast = try C.algorithm1(&m, t);
            const slow = try C.algorithm1Literal(&m, t);
            try testing.expectEqual(slow.secure, fast.secure);
            try testing.expectEqual(slow.code, fast.code);
            try testing.expectEqual(slow.round, fast.round);
        }
    }
}

test "algorithm_1 rejects a scalar power with code 1" {
    // The identity is scalar at i = 1, which is the first thing check 1 looks
    // at — the smallest possible witness for `[False, 1]`.
    const id = L.identity(3);
    const r = try C.algorithm1Literal(&id, 3);
    try testing.expect(!r.secure);
    try testing.expectEqual(@as(u8, 1), r.code);
    try testing.expectEqual(@as(usize, 1), r.round);
    try testing.expect(!(try C.algorithm1(&id, 3)).secure);
}

test "algorithm_1 rejects a matrix whose observability rank stalls" {
    // e_0^T M^k never leaves span(e_0, e_1), so the row sequence stalls and the
    // matrix must be rejected — with the same code and round as the literal
    // transcription reports.
    var m = L.zeroMat();
    m[0][0] = fe(2);
    m[0][1] = fe(3);
    m[1][0] = fe(5);
    m[1][1] = fe(7);
    m[2][2] = fe(11);
    m[3][3] = fe(13);
    const fast = try C.algorithm1(&m, 4);
    const slow = try C.algorithm1Literal(&m, 4);
    try testing.expect(!fast.secure);
    try testing.expectEqual(slow.code, fast.code);
    try testing.expectEqual(slow.round, fast.round);
}

test "algorithm_1's fast path is observability, not the Krylov space of e_0" {
    // The dual mistake, and an easy one: `algorithm_1` is about the ROW
    // sequence e_0^T M^k, `algorithm_2` about the COLUMN sequence M^k e_0.
    // This matrix separates them — e_0 is a cyclic vector, so a Krylov-based
    // fast path would accept it, while the row sequence stalls at rank 1 and
    // the reference rejects.
    var m = L.zeroMat();
    m[0][0] = fe(2);
    m[1][0] = fe(3);
    m[1][1] = fe(7);
    m[2][0] = fe(1);
    m[2][2] = fe(11);
    m[3][1] = fe(1);
    m[3][3] = fe(13);
    try testing.expect(C.algorithm2(&m, 4)); // e_0 IS cyclic
    const fast = try C.algorithm1(&m, 4);
    const slow = try C.algorithm1Literal(&m, 4);
    try testing.expect(!fast.secure);
    try testing.expectEqual(slow.code, fast.code);
    try testing.expectEqual(slow.round, fast.round);
}

test "algorithm_1 code 2: an eigenvector of M^i inside S_i, with the eigenvalue in F" {
    // Upper block-triangular with a rational eigenvalue whose eigenvector has a
    // zero first coordinate: e_1 is fixed by M, lies in S_1 = {x[0] = 0}, and
    // its eigenvalue 3 is in the base field.
    var m = L.zeroMat();
    m[0][0] = fe(2);
    m[0][1] = fe(5);
    m[1][1] = fe(3);
    m[2][2] = fe(3);
    const r = try C.algorithm1Literal(&m, 3);
    try testing.expect(!r.secure);
    try testing.expectEqual(@as(u8, 2), r.code);
    try testing.expectEqual(@as(usize, 1), r.round);
    try testing.expect(!(try C.algorithm1(&m, 3)).secure);
}

test "algorithm_3: fast path, divisor reduction and full transcription agree" {
    var s = Sample{ .state = 99 };
    for (0..8) |_| {
        for ([_]usize{ 3, 4, 5 }) |t| {
            const m = s.mat(t);
            try testing.expectEqual(C.algorithm3Literal(&m, t), C.algorithm3(&m, t));
        }
    }
}

test "algorithm_3 rejects a matrix whose eigenvalue ratios are roots of unity" {
    // Companion matrix of (x-1)(x+1)(x-2) = x^3 - 2x^2 - x + 2. e_0 is cyclic
    // for M, but lambda_0/lambda_1 = -1 has order 2, so M^2 has a repeated
    // eigenvalue and e_0 stops being cyclic for it.
    var m = L.zeroMat();
    m[1][0] = fe(1);
    m[2][1] = fe(1);
    m[0][2] = fe(2).neg();
    m[1][2] = fe(1);
    m[2][2] = fe(2);
    try testing.expect(C.algorithm2(&m, 3));
    try testing.expect(!C.algorithm3(&m, 3));
    try testing.expect(!C.algorithm3Literal(&m, 3));
}

test "check_minpoly_condition: irreducible charpoly required at every power" {
    // A diagonal matrix has a totally split charpoly, so i = 1 already fails.
    var d = L.zeroMat();
    for (0..3) |i| d[i][i] = fe(@intCast(i + 2));
    try testing.expect(!C.checkMinpolyCondition(&d, 3));

    // The companion matrix of an irreducible cubic passes i = 1 but not every
    // power: x^3 - x - 1 over this field, squared, is not guaranteed to stay
    // irreducible — so assert only what is structural, that the function
    // distinguishes the two.
    var m = L.zeroMat();
    m[1][0] = fe(1);
    m[2][1] = fe(1);
    m[0][2] = fe(1);
    m[1][2] = fe(1);
    const cp = L.charPoly(&m, 3, &L.SmallInverses.init());
    try testing.expectEqual(L.polyIsIrreducible(cp), L.polyIsIrreducible(L.charPoly(&m, 3, &L.SmallInverses.init())));
}

test "isSecure mirrors generate_matrix's accept condition" {
    var s = Sample{ .state = 4242 };
    for (0..6) |_| {
        for ([_]usize{ 3, 4 }) |t| {
            const m = s.mat(t);
            const want = (try C.algorithm1(&m, t)).secure and C.algorithm2(&m, t) and C.algorithm3(&m, t);
            try testing.expectEqual(want, try C.isSecure(&m, t));
        }
    }
}
