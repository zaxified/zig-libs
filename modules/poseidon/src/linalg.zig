// SPDX-License-Identifier: MIT
//! `linalg` — the small `GF(p)` linear-algebra and univariate-polynomial layer
//! that `mds_security.zig` needs, and that nothing else in this repository has
//! (yet) had a use for.
//!
//! ## Why it lives here and not in its own module
//!
//! `CONVENTIONS.md` §3 ("recursive sub-libraries") says: prefer std, and only
//! promote a building block to its own module when std has a real gap **and**
//! owning it long-term makes sense. Both halves matter here. std has the gap —
//! there is no matrix or polynomial arithmetic over a prime field anywhere in
//! `std` — but the *shape* of this layer is dictated entirely by one caller:
//! comptime-capacity `n x n` matrices over whichever `Fr` struct the parameter
//! set uses, no allocator, no runtime dimensions beyond a `n <= n_max` bound,
//! and exactly the operation set the four subspace-trail checks need. A
//! general "linear algebra over `GF(p)`" module would have to answer questions
//! this caller never asks (allocation, dynamic shapes, solve/LU/determinant as
//! a public surface, which field abstraction it accepts) and there is no second
//! consumer today to answer them for. Speculatively inventing that API is
//! exactly the "novel design from scratch" §1 warns against.
//!
//! So: module-private file, deliberately generic over `Fr` and carrying **no**
//! Poseidon vocabulary, so that promoting it to `modules/gfmat` the day a
//! second consumer appears (Poseidon2 / GMiMC / Rescue parameter generation,
//! or any other subspace-trail analysis) is a file move plus a README, not a
//! rewrite.
//!
//! ## What is in here
//!
//!   - **Matrices** — matrix/vector products, powers, trace. Fixed capacity
//!     `n_max`, runtime order `n <= n_max`.
//!   - **`Echelon`** — an incremental row-echelon accumulator used for rank,
//!     span membership and subspace equality. **Division-free**: a reduction
//!     step is `v := v*pivot - row*v[col]`, never `v / pivot`.
//!   - **`kernel`** — a basis of `{x : R x = 0}`.
//!   - **Polynomials** — add/mul/pseudo-remainder/gcd/derivative, modular
//!     exponentiation, squarefree test, Rabin irreducibility, and the roots of
//!     a polynomial **in the base field** (`gcd(f, x^p - x)` followed by
//!     Cantor-Zassenhaus equal-degree splitting).
//!   - **`charPoly`** (Faddeev-LeVerrier) and **`orderPoly`** (the minimal
//!     polynomial of a single vector under `M`).
//!
//! ## The one performance rule
//!
//! **Field inversion is ~380 field multiplications** here (`Fr.inv` is Fermat,
//! a full constant-time 254-bit ladder), so an algorithm that inverts every
//! pivot is two orders of magnitude off. Everything on a hot path in this file
//! is therefore division-free, and the few places that genuinely need pivots
//! normalised (kernel back-substitution, making a gcd monic, Newton's
//! identities' `1/k`) take **one** inversion for the whole batch via
//! `batchInv`. Nothing here is constant time, and nothing here should ever see
//! a secret: it consumes public parameters only.

const std = @import("std");

/// `Fr` must supply `zero`, `one`, `encoded_bytes`, `fromBytes`, `add`, `sub`,
/// `neg`, `mul`, `square`, `inv`, `eql`, `isZero`. `p_be` is the field modulus
/// big-endian (needed by the `x^p`-flavoured polynomial routines, which are an
/// *integer* statement about the field size and cannot be phrased in `Fr`).
/// `n_max` is the largest matrix order this instantiation will see.
pub fn Linalg(comptime Fr: type, comptime p_be: []const u8, comptime n_max: usize) type {
    return struct {
        pub const Vec = [n_max]Fr;
        pub const Mat = [n_max][n_max]Fr;

        /// Coefficient capacity. A product of two degree-`n_max` polynomials
        /// has degree `2*n_max`, hence `2*n_max + 1` coefficients; one spare
        /// slot keeps the reduction loops from having to special-case the top.
        pub const poly_cap = 2 * n_max + 2;

        // ── small helpers ───────────────────────────────────────────────────

        /// A small non-negative integer as a field element. Used for `1/k` in
        /// Newton's identities and for the Cantor-Zassenhaus shift constants —
        /// never for anything a caller supplies.
        pub fn fromU64(v: u64) Fr {
            var be: [Fr.encoded_bytes]u8 = @splat(0);
            std.mem.writeInt(u64, be[Fr.encoded_bytes - 8 ..][0..8], v, .big);
            return Fr.fromBytes(be) catch unreachable; // 2^64 < p for every field here
        }

        /// Montgomery batch inversion: `k` inverses for **one** `Fr.inv` plus
        /// `3(k-1)` multiplications. Every input must be non-zero.
        pub fn batchInv(in: []const Fr, out: []Fr) error{NotInvertible}!void {
            std.debug.assert(in.len == out.len);
            if (in.len == 0) return;
            var acc = Fr.one;
            for (in, 0..) |x, i| {
                out[i] = acc; // product of in[0..i)
                acc = acc.mul(x);
            }
            var run = try acc.inv();
            var i = in.len;
            while (i > 0) {
                i -= 1;
                out[i] = out[i].mul(run);
                run = run.mul(in[i]);
            }
        }

        // ── matrices ────────────────────────────────────────────────────────

        pub fn zeroVec() Vec {
            return @splat(Fr.zero);
        }

        pub fn zeroMat() Mat {
            return @splat(@as(Vec, @splat(Fr.zero)));
        }

        pub fn identity(n: usize) Mat {
            var m = zeroMat();
            for (0..n) |i| m[i][i] = Fr.one;
            return m;
        }

        pub fn basisVec(i: usize) Vec {
            var v = zeroVec();
            v[i] = Fr.one;
            return v;
        }

        /// `M * v` (the reference script's convention: `new[i] = Σ_j M[i][j] v[j]`).
        pub fn matVec(m: *const Mat, v: *const Vec, n: usize) Vec {
            var out = zeroVec();
            for (0..n) |i| {
                var acc = Fr.zero;
                for (0..n) |j| acc = acc.add(m[i][j].mul(v[j]));
                out[i] = acc;
            }
            return out;
        }

        /// `v^T * M` — the *row* form. `rowOf(M^k, 0)` is `e_0^T M^k`, which is
        /// what the subspace-trail constraints are built from.
        pub fn vecMat(v: *const Vec, m: *const Mat, n: usize) Vec {
            var out = zeroVec();
            for (0..n) |j| {
                var acc = Fr.zero;
                for (0..n) |i| acc = acc.add(v[i].mul(m[i][j]));
                out[j] = acc;
            }
            return out;
        }

        pub fn matMul(a: *const Mat, b: *const Mat, n: usize) Mat {
            var out = zeroMat();
            for (0..n) |i| {
                for (0..n) |k| {
                    const aik = a[i][k];
                    if (aik.isZero()) continue;
                    for (0..n) |j| out[i][j] = out[i][j].add(aik.mul(b[k][j]));
                }
            }
            return out;
        }

        /// `M^e`, by repeated squaring. `e = 0` is the identity.
        pub fn matPow(m: *const Mat, e: usize, n: usize) Mat {
            var result = identity(n);
            var base = m.*;
            var k = e;
            while (k > 0) {
                if (k & 1 == 1) result = matMul(&result, &base, n);
                k >>= 1;
                if (k > 0) base = matMul(&base, &base, n);
            }
            return result;
        }

        pub fn matEql(a: *const Mat, b: *const Mat, n: usize) bool {
            for (0..n) |i| for (0..n) |j| {
                if (!a[i][j].eql(b[i][j])) return false;
            };
            return true;
        }

        pub fn trace(m: *const Mat, n: usize) Fr {
            var acc = Fr.zero;
            for (0..n) |i| acc = acc.add(m[i][i]);
            return acc;
        }

        // ── row echelon ─────────────────────────────────────────────────────

        /// An incremental, **division-free** row-echelon accumulator over
        /// `F^n`: `add` returns whether the vector enlarged the span,
        /// `contains` tests membership, `rank` is the dimension.
        ///
        /// The stored rows are *not* normalised — pivots are whatever they
        /// happened to be — because normalising costs one inversion per pivot
        /// and nothing here needs a canonical form. Subspace equality is done
        /// as "same rank plus mutual containment", which is basis-independent.
        pub const Echelon = struct {
            n: usize,
            rank: usize = 0,
            rows: [n_max]Vec = undefined,
            pivot: [n_max]usize = undefined,

            pub fn init(n: usize) Echelon {
                return .{ .n = n };
            }

            /// `v` reduced against the stored rows. Zero iff `v` was in the
            /// span. The result is `v` scaled by a non-zero factor (the product
            /// of the pivots actually used), which membership and rank tests do
            /// not care about.
            pub fn reduce(self: *const Echelon, v_in: Vec) Vec {
                var v = v_in;
                for (0..self.rank) |i| {
                    const c = self.pivot[i];
                    if (v[c].isZero()) continue;
                    const f = v[c];
                    const g = self.rows[i][c];
                    for (0..self.n) |j| v[j] = v[j].mul(g).sub(self.rows[i][j].mul(f));
                }
                return v;
            }

            /// Adds `v` to the span; true iff the rank grew.
            pub fn add(self: *Echelon, v: Vec) bool {
                const r = self.reduce(v);
                var c: usize = 0;
                while (c < self.n) : (c += 1) {
                    if (!r[c].isZero()) break;
                }
                if (c == self.n) return false;
                self.rows[self.rank] = r;
                self.pivot[self.rank] = c;
                self.rank += 1;
                return true;
            }

            pub fn contains(self: *const Echelon, v: Vec) bool {
                const r = self.reduce(v);
                for (0..self.n) |j| {
                    if (!r[j].isZero()) return false;
                }
                return true;
            }
        };

        /// `span(a) == span(b)`. Equal rank plus one-way containment is enough,
        /// and it needs no canonical form — which is why `Echelon` does not
        /// pay for one.
        pub fn spanEql(a: *const Echelon, b: *const Echelon) bool {
            if (a.rank != b.rank) return false;
            for (0..a.rank) |i| {
                if (!b.contains(a.rows[i])) return false;
            }
            return true;
        }

        /// A basis of `{ x in F^n : rows[i] · x = 0 for every i }`, written to
        /// `out`; returns the dimension.
        ///
        /// This is the one place that normalises pivots, so it costs exactly
        /// one `Fr.inv` (via `batchInv`) regardless of `n`.
        pub fn kernel(rows: []const Vec, n: usize, out: *[n_max]Vec) usize {
            var e = Echelon.init(n);
            for (rows) |r| _ = e.add(r);

            // Sort the echelon rows by pivot column (`Echelon.add` does not
            // keep them ordered) so that back-substitution can go bottom-up.
            var order: [n_max]usize = undefined;
            for (0..e.rank) |i| order[i] = i;
            std.sort.insertion(usize, order[0..e.rank], &e, struct {
                fn lt(ctx: *const Echelon, x: usize, y: usize) bool {
                    return ctx.pivot[x] < ctx.pivot[y];
                }
            }.lt);

            // Reduced row echelon form: normalise pivots, then clear above.
            var piv_vals: [n_max]Fr = undefined;
            for (0..e.rank) |i| piv_vals[i] = e.rows[order[i]][e.pivot[order[i]]];
            var piv_inv: [n_max]Fr = undefined;
            batchInv(piv_vals[0..e.rank], piv_inv[0..e.rank]) catch unreachable; // pivots are non-zero

            var r: [n_max]Vec = undefined;
            var pcol: [n_max]usize = undefined;
            for (0..e.rank) |i| {
                const src = e.rows[order[i]];
                var row: Vec = undefined;
                for (0..n) |j| row[j] = src[j].mul(piv_inv[i]);
                r[i] = row;
                pcol[i] = e.pivot[order[i]];
            }
            var i = e.rank;
            while (i > 0) {
                i -= 1;
                var k: usize = 0;
                while (k < i) : (k += 1) {
                    const f = r[k][pcol[i]];
                    if (f.isZero()) continue;
                    for (0..n) |j| r[k][j] = r[k][j].sub(r[i][j].mul(f));
                }
            }

            var is_pivot: [n_max]bool = @splat(false);
            for (0..e.rank) |k| is_pivot[pcol[k]] = true;

            var dim: usize = 0;
            for (0..n) |free_col| {
                if (is_pivot[free_col]) continue;
                var v = zeroVec();
                v[free_col] = Fr.one;
                for (0..e.rank) |k| v[pcol[k]] = r[k][free_col].neg();
                out[dim] = v;
                dim += 1;
            }
            return dim;
        }

        // ── polynomials ─────────────────────────────────────────────────────

        /// A univariate polynomial over `F`, `c[i]` the coefficient of `x^i`.
        /// `deg == -1` is the zero polynomial.
        pub const Poly = struct {
            c: [poly_cap]Fr = @splat(Fr.zero),
            deg: isize = -1,

            pub fn lc(self: Poly) Fr {
                return if (self.deg < 0) Fr.zero else self.c[@intCast(self.deg)];
            }

            pub fn isZero(self: Poly) bool {
                return self.deg < 0;
            }

            pub fn eql(a: Poly, b: Poly) bool {
                if (a.deg != b.deg) return false;
                var i: isize = 0;
                while (i <= a.deg) : (i += 1) {
                    if (!a.c[@intCast(i)].eql(b.c[@intCast(i)])) return false;
                }
                return true;
            }
        };

        fn pnorm(p: *Poly) void {
            while (p.deg >= 0 and p.c[@intCast(p.deg)].isZero()) p.deg -= 1;
        }

        pub fn polyZero() Poly {
            return .{};
        }

        pub fn polyConst(v: Fr) Poly {
            var p = Poly{};
            p.c[0] = v;
            p.deg = 0;
            pnorm(&p);
            return p;
        }

        /// `x`.
        pub fn polyX() Poly {
            var p = Poly{};
            p.c[1] = Fr.one;
            p.deg = 1;
            return p;
        }

        pub fn polyFrom(coeffs: []const Fr) Poly {
            var p = Poly{};
            std.debug.assert(coeffs.len <= poly_cap);
            for (coeffs, 0..) |v, i| p.c[i] = v;
            p.deg = @as(isize, @intCast(coeffs.len)) - 1;
            pnorm(&p);
            return p;
        }

        pub fn polyAdd(a: Poly, b: Poly) Poly {
            var out = Poly{};
            out.deg = @max(a.deg, b.deg);
            var i: isize = 0;
            while (i <= out.deg) : (i += 1) {
                const k: usize = @intCast(i);
                out.c[k] = (if (i <= a.deg) a.c[k] else Fr.zero).add(if (i <= b.deg) b.c[k] else Fr.zero);
            }
            pnorm(&out);
            return out;
        }

        pub fn polySub(a: Poly, b: Poly) Poly {
            var out = Poly{};
            out.deg = @max(a.deg, b.deg);
            var i: isize = 0;
            while (i <= out.deg) : (i += 1) {
                const k: usize = @intCast(i);
                out.c[k] = (if (i <= a.deg) a.c[k] else Fr.zero).sub(if (i <= b.deg) b.c[k] else Fr.zero);
            }
            pnorm(&out);
            return out;
        }

        pub fn polyScale(a: Poly, s: Fr) Poly {
            if (s.isZero()) return polyZero();
            var out = a;
            var i: isize = 0;
            while (i <= a.deg) : (i += 1) out.c[@intCast(i)] = a.c[@intCast(i)].mul(s);
            return out;
        }

        pub fn polyMul(a: Poly, b: Poly) Poly {
            if (a.isZero() or b.isZero()) return polyZero();
            var out = Poly{};
            out.deg = a.deg + b.deg;
            std.debug.assert(out.deg < poly_cap);
            var i: isize = 0;
            while (i <= a.deg) : (i += 1) {
                const ai = a.c[@intCast(i)];
                if (ai.isZero()) continue;
                var j: isize = 0;
                while (j <= b.deg) : (j += 1) {
                    const k: usize = @intCast(i + j);
                    out.c[k] = out.c[k].add(ai.mul(b.c[@intCast(j)]));
                }
            }
            pnorm(&out);
            return out;
        }

        pub fn polyDeriv(a: Poly) Poly {
            if (a.deg <= 0) return polyZero();
            var out = Poly{};
            out.deg = a.deg - 1;
            var i: isize = 1;
            while (i <= a.deg) : (i += 1) {
                out.c[@intCast(i - 1)] = a.c[@intCast(i)].mul(fromU64(@intCast(i)));
            }
            pnorm(&out);
            return out;
        }

        /// `a mod f` for **monic** `f` — no inversion needed.
        pub fn polyRemMonic(a_in: Poly, f: Poly) Poly {
            std.debug.assert(f.deg >= 0);
            var a = a_in;
            while (a.deg >= f.deg) {
                const shift: usize = @intCast(a.deg - f.deg);
                const factor = a.c[@intCast(a.deg)];
                var i: isize = 0;
                while (i <= f.deg) : (i += 1) {
                    const k: usize = @intCast(i + @as(isize, @intCast(shift)));
                    a.c[k] = a.c[k].sub(f.c[@intCast(i)].mul(factor));
                }
                a.deg -= 1;
                pnorm(&a);
                if (a.deg < 0) break;
            }
            return a;
        }

        /// Quotient of `a` by **monic** `f`.
        pub fn polyDivMonic(a_in: Poly, f: Poly) Poly {
            std.debug.assert(f.deg >= 0);
            var a = a_in;
            var q = Poly{};
            if (a.deg < f.deg) return q;
            q.deg = a.deg - f.deg;
            while (a.deg >= f.deg) {
                const shift: usize = @intCast(a.deg - f.deg);
                const factor = a.c[@intCast(a.deg)];
                q.c[shift] = factor;
                var i: isize = 0;
                while (i <= f.deg) : (i += 1) {
                    const k: usize = @intCast(i + @as(isize, @intCast(shift)));
                    a.c[k] = a.c[k].sub(f.c[@intCast(i)].mul(factor));
                }
                a.deg -= 1;
                pnorm(&a);
                if (a.deg < 0) break;
            }
            pnorm(&q);
            return q;
        }

        /// Pseudo-remainder: the true remainder of `a` by `b` up to a non-zero
        /// scalar factor. Division-free, which is the only reason `polyGcd` is
        /// affordable. Callers must not depend on the scalar.
        pub fn polyPseudoRem(a_in: Poly, b: Poly) Poly {
            std.debug.assert(!b.isZero());
            var a = a_in;
            const lb = b.lc();
            while (a.deg >= b.deg) {
                const shift: usize = @intCast(a.deg - b.deg);
                const la = a.c[@intCast(a.deg)];
                // a := a*lc(b) - b*lc(a)*x^shift
                var i: isize = 0;
                while (i <= a.deg) : (i += 1) a.c[@intCast(i)] = a.c[@intCast(i)].mul(lb);
                i = 0;
                while (i <= b.deg) : (i += 1) {
                    const k: usize = @intCast(i + @as(isize, @intCast(shift)));
                    a.c[k] = a.c[k].sub(b.c[@intCast(i)].mul(la));
                }
                a.deg -= 1;
                pnorm(&a);
                if (a.deg < 0) break;
            }
            return a;
        }

        /// `gcd(a, b)`, up to a non-zero scalar factor (use `polyMakeMonic` if
        /// the exact value matters; degree and zero-ness do not depend on it).
        pub fn polyGcd(a_in: Poly, b_in: Poly) Poly {
            var a = a_in;
            var b = b_in;
            while (!b.isZero()) {
                const r = polyPseudoRem(a, b);
                a = b;
                b = r;
            }
            return a;
        }

        pub fn polyMakeMonic(a: Poly) error{NotInvertible}!Poly {
            if (a.isZero()) return a;
            const inv = try a.lc().inv();
            return polyScale(a, inv);
        }

        /// Squarefree over `F` — no repeated irreducible factor. `deg gcd(f, f')`
        /// is `0` exactly then (`p` is far larger than any degree here, so `f'`
        /// cannot vanish identically for `deg f >= 1`).
        pub fn polyIsSquarefree(f: Poly) bool {
            if (f.deg <= 0) return true;
            const g = polyGcd(f, polyDeriv(f));
            return g.deg == 0;
        }

        pub fn polyMulMod(a: Poly, b: Poly, f: Poly) Poly {
            return polyRemMonic(polyMul(a, b), f);
        }

        /// `base^e mod f` for **monic** `f`, `e` big-endian.
        pub fn polyPowMod(base: Poly, e_be: []const u8, f: Poly) Poly {
            var result = polyConst(Fr.one);
            const b = polyRemMonic(base, f);
            var started = false;
            for (e_be) |byte| {
                var bit: u3 = 7;
                while (true) : (bit -= 1) {
                    const set = (byte >> bit) & 1 == 1;
                    if (started) result = polyMulMod(result, result, f);
                    if (set) {
                        if (started) {
                            result = polyMulMod(result, b, f);
                        } else {
                            result = b;
                            started = true;
                        }
                    }
                    if (bit == 0) break;
                }
            }
            return result;
        }

        /// `x^p mod f` — the Frobenius image of `x`, the workhorse of both the
        /// root finder and the irreducibility test.
        pub fn polyFrobenius(f: Poly) Poly {
            return polyPowMod(polyX(), p_be, f);
        }

        pub const RootError = error{ NotInvertible, RootIsolationFailed };

        /// Every **distinct root of `f` that lies in the base field** `F`,
        /// written to `out`; returns how many there were.
        ///
        /// `gcd(f, x^p - x)` is the product of the distinct linear factors of
        /// `f` over `F`; Cantor-Zassenhaus equal-degree splitting then peels
        /// them apart. Note what this deliberately does **not** do: roots in an
        /// extension field are skipped, which is the same thing the reference
        /// script's `if (eigenspace[0] not in F): continue` does.
        pub fn polyRootsInField(f_in: Poly, out: *[n_max]Fr) RootError!usize {
            if (f_in.deg <= 0) return 0;
            const f = try polyMakeMonic(f_in);
            const fro = polyFrobenius(f);
            const h = polySub(fro, polyX());
            var g = polyGcd(f, h);
            if (g.deg <= 0) return 0;
            g = try polyMakeMonic(g);
            var count: usize = 0;
            try splitDistinctLinear(g, out, &count);
            return count;
        }

        /// `(p-1)/2`, big-endian — the Cantor-Zassenhaus exponent.
        const half_p_minus_1: [Fr.encoded_bytes]u8 = blk: {
            @setEvalBranchQuota(100_000);
            var v: u512 = 0;
            for (p_be) |byte| v = (v << 8) | byte;
            v = (v - 1) / 2;
            var be: [Fr.encoded_bytes]u8 = @splat(0);
            var i: usize = Fr.encoded_bytes;
            while (i > 0) {
                i -= 1;
                be[i] = @truncate(v);
                v >>= 8;
            }
            break :blk be;
        };

        /// `g` is monic, squarefree, and splits into distinct linear factors
        /// over `F`. Peel them off.
        fn splitDistinctLinear(g: Poly, out: *[n_max]Fr, count: *usize) RootError!void {
            if (g.deg <= 0) return;
            if (g.deg == 1) {
                out[count.*] = g.c[0].neg(); // g = x + c0
                count.* += 1;
                return;
            }
            // Deterministic shift sequence, so that `derive` stays a pure
            // function of its parameters. Each shift splits a non-trivial
            // factor off with probability ~1/2 for a random one, so 64 of them
            // failing is a "this cannot happen" that is reported rather than
            // looped on forever.
            var a: u64 = 1;
            while (a <= 64) : (a += 1) {
                var shifted = polyX();
                shifted.c[0] = fromU64(a);
                const h = polyPowMod(shifted, &half_p_minus_1, g);
                const d0 = polyGcd(g, polySub(h, polyConst(Fr.one)));
                if (d0.deg <= 0 or d0.deg >= g.deg) continue;
                const d = try polyMakeMonic(d0);
                try splitDistinctLinear(d, out, count);
                try splitDistinctLinear(try polyMakeMonic(polyDivMonic(g, d)), out, count);
                return;
            }
            return error.RootIsolationFailed;
        }

        /// Rabin's irreducibility test for a **monic** `f` over `F`:
        /// `x^(p^n) == x (mod f)` and `gcd(x^(p^(n/q)) - x, f) == 1` for every
        /// prime `q | n`.
        ///
        /// Cost is `n` modular exponentiations, i.e. `O(n * log p * n^2)` field
        /// multiplications — fine for the `check_minpoly_condition` use it was
        /// written for, which is not on the MDS generation path.
        pub fn polyIsIrreducible(f: Poly) bool {
            if (f.deg <= 0) return false;
            if (f.deg == 1) return true;
            const n: usize = @intCast(f.deg);

            var cur = polyX();
            var k: usize = 1;
            while (k <= n) : (k += 1) {
                cur = polyPowMod(cur, p_be, f); // cur = x^(p^k) mod f
                if (k < n and n % k == 0 and isPrime(n / k)) {
                    const g = polyGcd(f, polySub(cur, polyX()));
                    if (g.deg != 0) return false;
                }
            }
            return cur.eql(polyX());
        }

        fn isPrime(v: usize) bool {
            if (v < 2) return false;
            var d: usize = 2;
            while (d * d <= v) : (d += 1) {
                if (v % d == 0) return false;
            }
            return true;
        }

        // ── characteristic and order polynomials ────────────────────────────

        /// `1/1, 1/2, … 1/n_max`, for **one** field inversion.
        ///
        /// Newton's identities need `1/k`, and both `charPoly` and
        /// `polyFromPowerSums` are called in a loop — `algorithm_3` calls the
        /// latter `2t` times per candidate matrix. An inversion is ~380
        /// multiplications, so building this once instead of per call is worth
        /// roughly a fifth of the whole check.
        pub const SmallInverses = struct {
            v: [n_max]Fr,

            pub fn init() SmallInverses {
                var ks: [n_max]Fr = undefined;
                for (0..n_max) |i| ks[i] = fromU64(@intCast(i + 1));
                var out: SmallInverses = undefined;
                batchInv(&ks, &out.v) catch unreachable; // 1..n_max < p
                return out;
            }

            /// `1/k`, `k >= 1`.
            pub fn of(self: *const SmallInverses, k: usize) Fr {
                return self.v[k - 1];
            }
        };

        /// The characteristic polynomial of `A`, by Faddeev-LeVerrier. Monic of
        /// degree `n`. Costs `n` matrix multiplications (`O(n^4)`) — used off
        /// the hot path.
        pub fn charPoly(a: *const Mat, n: usize, inv: *const SmallInverses) Poly {
            var coeff: [n_max + 1]Fr = @splat(Fr.zero);
            coeff[n] = Fr.one;
            var m = zeroMat(); // M_0 = 0
            for (1..n + 1) |k| {
                // M_k = A*M_(k-1) + c_(n-k+1) * I
                m = matMul(a, &m, n);
                for (0..n) |i| m[i][i] = m[i][i].add(coeff[n - k + 1]);
                const am = matMul(a, &m, n);
                coeff[n - k] = trace(&am, n).mul(inv.of(k)).neg();
            }
            return polyFrom(coeff[0 .. n + 1]);
        }

        /// The **order polynomial** of `v` under `M`: the monic generator of
        /// `{ g : g(M) v = 0 }`. Its degree is the dimension of the Krylov
        /// space of `v`, so `deg == n` is exactly "`v` is a cyclic vector",
        /// and then it equals both the minimal and the characteristic
        /// polynomial of `M`.
        ///
        /// Costs `O(n^3)` — this is the cheap route to `charPoly` whenever a
        /// cyclic vector is at hand.
        pub fn orderPoly(m: *const Mat, v: *const Vec, n: usize) Poly {
            // Augmented elimination: each stored row carries the combination of
            // v, Mv, M^2 v, ... that produced it, so the first row that reduces
            // to zero hands back the dependency directly.
            var rows: [n_max]Vec = undefined;
            var combo: [n_max][n_max + 1]Fr = undefined;
            var pivot: [n_max]usize = undefined;
            var rank: usize = 0;

            var u = v.*;
            var step: usize = 0;
            while (step <= n) : (step += 1) {
                var cur = u;
                var cc: [n_max + 1]Fr = @splat(Fr.zero);
                cc[step] = Fr.one;

                for (0..rank) |i| {
                    const c = pivot[i];
                    if (cur[c].isZero()) continue;
                    const f = cur[c];
                    const g = rows[i][c];
                    for (0..n) |j| cur[j] = cur[j].mul(g).sub(rows[i][j].mul(f));
                    for (0..step + 1) |j| cc[j] = cc[j].mul(g).sub(combo[i][j].mul(f));
                }

                var c: usize = 0;
                while (c < n) : (c += 1) {
                    if (!cur[c].isZero()) break;
                }
                if (c == n) {
                    // Dependency found: Σ cc[j] * M^j v = 0.
                    var p = polyFrom(cc[0 .. step + 1]);
                    p = polyMakeMonic(p) catch unreachable; // cc[step] != 0
                    return p;
                }
                rows[rank] = cur;
                combo[rank] = cc;
                pivot[rank] = c;
                rank += 1;
                u = matVec(m, &u, n);
            }
            unreachable; // n+1 vectors in F^n are always dependent
        }

        // ── power sums ──────────────────────────────────────────────────────

        /// `s[j] = Σ_i λ_i^j` for the roots `λ_i` of the monic degree-`n` `f`,
        /// for `j = 0 .. count-1`, straight from Newton's identities — no
        /// matrix powers and no root finding.
        ///
        /// `s[0] = n`; for `1 <= k <= n`,
        /// `s[k] = -Σ_(i=1..k-1) a_(n-i) s_(k-i) - k*a_(n-k)`; and for `k > n`
        /// the same recurrence without the trailing term (`a` are `f`'s
        /// coefficients). `count` may exceed `n` freely: that is the point.
        pub fn powerSums(f: Poly, n: usize, s: []Fr) void {
            std.debug.assert(f.deg == @as(isize, @intCast(n)));
            if (s.len == 0) return;
            s[0] = fromU64(@intCast(n));
            for (1..s.len) |k| {
                var acc = Fr.zero;
                if (k <= n) {
                    for (1..k) |i| acc = acc.add(f.c[n - i].mul(s[k - i]));
                    acc = acc.add(fromU64(@intCast(k)).mul(f.c[n - k]));
                } else {
                    for (1..n + 1) |i| acc = acc.add(f.c[n - i].mul(s[k - i]));
                }
                s[k] = acc.neg();
            }
        }

        /// The monic degree-`n` polynomial whose roots are the `λ_i` implied by
        /// the power sums `s[1..n]`, via Newton's identities
        /// (`k*e_k = Σ_(i=1..k) (-1)^(i-1) e_(k-i) s_i`, then
        /// `f = Σ_k (-1)^k e_k x^(n-k)`).
        ///
        /// Used to turn `tr(M^(r*k))` into `charpoly(M^r)` without ever forming
        /// `M^r`.
        pub fn polyFromPowerSums(s: []const Fr, n: usize, inv: *const SmallInverses) Poly {
            var e: [n_max + 1]Fr = @splat(Fr.zero);
            e[0] = Fr.one;
            for (1..n + 1) |k| {
                var acc = Fr.zero;
                for (1..k + 1) |i| {
                    const term = e[k - i].mul(s[i]);
                    acc = if (i % 2 == 1) acc.add(term) else acc.sub(term);
                }
                e[k] = acc.mul(inv.of(k));
            }
            var coeff: [n_max + 1]Fr = @splat(Fr.zero);
            for (0..n + 1) |k| {
                coeff[n - k] = if (k % 2 == 0) e[k] else e[k].neg();
            }
            return polyFrom(coeff[0 .. n + 1]);
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const bn254 = @import("bn254");
const testing = std.testing;

const T = 6;
const La = Linalg(bn254.Fr, &bn254.scalar.r_bytes, T);
const TFr = bn254.Fr;

fn small() La.SmallInverses {
    return .init();
}

fn fe(v: u64) TFr {
    return La.fromU64(v);
}

/// A deterministic non-cryptographic source of "arbitrary" field elements, so
/// the tests below are reproducible without an RNG dependency.
const Sample = struct {
    state: u64,
    fn next(self: *Sample) TFr {
        self.state = self.state *% 6364136223846793005 +% 1442695040888963407;
        return fe((self.state >> 11) | 1);
    }
    fn mat(self: *Sample, n: usize) La.Mat {
        var m = La.zeroMat();
        for (0..n) |i| for (0..n) |j| {
            m[i][j] = self.next();
        };
        return m;
    }
};

test "matPow agrees with repeated multiplication" {
    var s = Sample{ .state = 7 };
    const m = s.mat(4);
    var acc = La.identity(4);
    for (0..7) |k| {
        try testing.expect(La.matEql(&acc, &La.matPow(&m, k, 4), 4));
        acc = La.matMul(&acc, &m, 4);
    }
}

test "Echelon: rank, membership and division-free reduction" {
    var e = La.Echelon.init(3);
    try testing.expect(e.add(.{ fe(1), fe(2), fe(3), fe(0), fe(0), fe(0) }));
    try testing.expect(e.add(.{ fe(0), fe(1), fe(1), fe(0), fe(0), fe(0) }));
    try testing.expectEqual(@as(usize, 2), e.rank);
    // (2,5,7) = 2*(1,2,3) + 1*(0,1,1)
    try testing.expect(e.contains(.{ fe(2), fe(5), fe(7), fe(0), fe(0), fe(0) }));
    try testing.expect(!e.add(.{ fe(2), fe(5), fe(7), fe(0), fe(0), fe(0) }));
    try testing.expect(!e.contains(.{ fe(0), fe(0), fe(1), fe(0), fe(0), fe(0) }));
}

test "kernel of a rank-2 constraint set has the right dimension and vanishes" {
    const rows = [_]La.Vec{
        .{ fe(1), fe(2), fe(3), fe(4), fe(0), fe(0) },
        .{ fe(0), fe(1), fe(1), fe(1), fe(0), fe(0) },
    };
    var basis: [T]La.Vec = undefined;
    const dim = La.kernel(&rows, 4, &basis);
    try testing.expectEqual(@as(usize, 2), dim);
    for (basis[0..dim]) |v| {
        for (rows) |r| {
            var acc = TFr.zero;
            for (0..4) |j| acc = acc.add(r[j].mul(v[j]));
            try testing.expect(acc.isZero());
        }
    }
    // The basis is independent.
    var e = La.Echelon.init(4);
    for (basis[0..dim]) |v| try testing.expect(e.add(v));
}

test "charPoly: Cayley-Hamilton, and it matches orderPoly for a cyclic vector" {
    var s = Sample{ .state = 11 };
    const m = s.mat(5);
    const cp = La.charPoly(&m, 5, &small());
    try testing.expectEqual(@as(isize, 5), cp.deg);

    // p(M) == 0.
    var acc = La.zeroMat();
    var pw = La.identity(5);
    var i: usize = 0;
    while (i <= 5) : (i += 1) {
        for (0..5) |r| for (0..5) |c| {
            acc[r][c] = acc[r][c].add(cp.c[i].mul(pw[r][c]));
        };
        pw = La.matMul(&pw, &m, 5);
    }
    try testing.expect(La.matEql(&acc, &La.zeroMat(), 5));

    // A random matrix is cyclic w.r.t. e_0 with overwhelming probability, and
    // then the order polynomial IS the characteristic polynomial.
    const op = La.orderPoly(&m, &La.basisVec(0), 5);
    try testing.expectEqual(@as(isize, 5), op.deg);
    try testing.expect(op.eql(cp));
}

test "orderPoly reports the true Krylov dimension on a non-cyclic vector" {
    // Block diagonal: e_0 only ever sees the 2x2 top-left block.
    var m = La.zeroMat();
    m[0][0] = fe(2);
    m[0][1] = fe(3);
    m[1][0] = fe(5);
    m[1][1] = fe(7);
    m[2][2] = fe(11);
    m[3][3] = fe(13);
    const op = La.orderPoly(&m, &La.basisVec(0), 4);
    try testing.expectEqual(@as(isize, 2), op.deg);
    // x^2 - 9x - 1  (trace 9, det 14-15 = -1)
    try testing.expect(op.c[1].eql(fe(9).neg()));
    try testing.expect(op.c[0].eql(TFr.one.neg()));
}

test "polyGcd, squarefree detection and monic normalisation" {
    // (x-1)(x-2) and (x-2)(x-3) share (x-2).
    const a = La.polyMul(La.polyFrom(&.{ fe(1).neg(), TFr.one }), La.polyFrom(&.{ fe(2).neg(), TFr.one }));
    const b = La.polyMul(La.polyFrom(&.{ fe(2).neg(), TFr.one }), La.polyFrom(&.{ fe(3).neg(), TFr.one }));
    const g = try La.polyMakeMonic(La.polyGcd(a, b));
    try testing.expectEqual(@as(isize, 1), g.deg);
    try testing.expect(g.c[0].eql(fe(2).neg()));

    try testing.expect(La.polyIsSquarefree(a));
    const sq = La.polyMul(a, La.polyFrom(&.{ fe(1).neg(), TFr.one })); // (x-1)^2 (x-2)
    try testing.expect(!La.polyIsSquarefree(sq));
}

test "polyRootsInField finds base-field roots and skips the others" {
    // (x-3)(x-10)(x^2+1). -1 is a QR mod this prime? Either way the quadratic
    // is handled by whatever it factors into; the two rational roots must show.
    const lin = La.polyMul(
        La.polyFrom(&.{ fe(3).neg(), TFr.one }),
        La.polyFrom(&.{ fe(10).neg(), TFr.one }),
    );
    var out: [T]TFr = undefined;
    const n = try La.polyRootsInField(lin, &out);
    try testing.expectEqual(@as(usize, 2), n);
    var saw3 = false;
    var saw10 = false;
    for (out[0..n]) |r| {
        if (r.eql(fe(3))) saw3 = true;
        if (r.eql(fe(10))) saw10 = true;
    }
    try testing.expect(saw3 and saw10);

    // A quadratic with no root in F: x^2 - q for a non-residue q. Find one.
    var q: u64 = 2;
    const irr = while (q < 40) : (q += 1) {
        const f = La.polyFrom(&.{ fe(q).neg(), TFr.zero, TFr.one });
        if (try La.polyRootsInField(f, &out) == 0) break f;
    } else unreachable;
    try testing.expectEqual(@as(usize, 0), try La.polyRootsInField(irr, &out));
    try testing.expect(La.polyIsIrreducible(irr));
}

test "polyIsIrreducible: linear yes, split-product no" {
    try testing.expect(La.polyIsIrreducible(La.polyFrom(&.{ fe(5), TFr.one })));
    const split = La.polyMul(
        La.polyFrom(&.{ fe(3).neg(), TFr.one }),
        La.polyFrom(&.{ fe(10).neg(), TFr.one }),
    );
    try testing.expect(!La.polyIsIrreducible(split));
}

test "power sums round-trip through Newton's identities" {
    var s = Sample{ .state = 29 };
    const m = s.mat(5);
    const cp = La.charPoly(&m, 5, &small());

    var sums: [11]TFr = undefined;
    La.powerSums(cp, 5, &sums);

    // s[k] must equal tr(M^k) — an independent route to the same numbers.
    var pw = La.identity(5);
    for (0..11) |k| {
        try testing.expect(sums[k].eql(La.trace(&pw, 5)));
        pw = La.matMul(&pw, &m, 5);
    }

    // And the coefficients come back from the sums.
    const back = La.polyFromPowerSums(sums[0..6], 5, &small());
    try testing.expect(back.eql(cp));
}

test "polyFromPowerSums reconstructs charpoly(M^r) without forming M^r" {
    var s = Sample{ .state = 31 };
    const m = s.mat(4);
    const cp = La.charPoly(&m, 4, &small());
    var sums: [40]TFr = undefined;
    La.powerSums(cp, 4, &sums);

    for ([_]usize{ 2, 3, 5, 9 }) |r| {
        var picked: [5]TFr = undefined;
        picked[0] = La.fromU64(4);
        for (1..5) |k| picked[k] = sums[r * k];
        const got = La.polyFromPowerSums(&picked, 4, &small());
        const want = La.charPoly(&La.matPow(&m, r, 4), 4, &small());
        try testing.expect(got.eql(want));
    }
}
