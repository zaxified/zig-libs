// SPDX-License-Identifier: MIT

//! montint — constant-time Montgomery modular arithmetic over arbitrary ODD
//! moduli (prime OR composite: RSA/Paillier N, VDF group order, pairing-field
//! primes), on full radix-2^64 limbs.
//!
//! `Modint(max_bits)` is the analogue of `std.crypto.ff.Modulus`, built to
//! *beat* it: `ff` reserves a carry bit per limb (63-bit redundant limbs) and
//! does a 4-way half-limb `mulWide`, which forecloses the host add-with-carry
//! and widening-multiply instructions — the measured ~8–29× gap vs OpenSSL
//! across `rsa`/`paillier`/`vdf` (see `SPEC.md`). This module uses full 2^64
//! limbs so the amd64 `MULX/ADCX/ADOX` core (gated, `asm_core.zig`) can reach
//! OpenSSL-competitive speed, with this portable CIOS path as the fallback on
//! every other arch AND as the correctness oracle the asm core is diffed
//! against.
//!
//! Representation: values are `[limbs_len]u64`, little-endian. Montgomery-domain
//! and normal-domain values share the type; the domain is tracked by naming
//! convention (`*_mont`), like the internal helpers of `ff`. Convert at the
//! boundary with `toMontgomery`/`fromMontgomery`; keep values Montgomery-
//! resident across a modexp.

const std = @import("std");
const builtin = @import("builtin");
const limbs = @import("limbs.zig");
const gate = @import("gate.zig");
const asm_core = @import("asm_core.zig");

/// Errors surfaced when constructing a modulus or reducing an input.
pub const Error = error{ EvenModulus, ModulusTooSmall, NonCanonical, Overflow };

/// Whether the accelerated amd64 core is BOTH available on this target and
/// switched on. While `gate.asm_core_implemented` is `false` this is always
/// `false` and every operation runs on the portable CIOS oracle.
pub const asm_active = asm_core.supported and gate.asm_core_implemented;

/// Small-L dispatch cutoff (limb count `L`, i.e. `bits/64`). The
/// `MULX/ADCX/ADOX` asm core only pays off for LARGE moduli: the asm block runs
/// runtime-`n` loops (trip-count setup, remainder handling, the cross-row
/// register shuffle), whereas the portable CIOS is comptime-fully-unrolled with
/// zero loop bookkeeping, so at small L the asm overhead dominates the handful
/// of limb products. Measured on this repo's host (Kaby Lake, ReleaseFast; see
/// `SPEC.md` "256-bit regression / small-L dispatch") the asm modmul is:
///   L=4  (256b): ~2.4× SLOWER · L=8 (512b): ~1.06× slower · L=16 (1024b):
///   ~1.07× slower · L=32 (2048b): ~1.43× FASTER · L=64 (4096b): ~1.75× faster.
/// So breakeven is ~1.5–2k bit here (higher than the canonical ~512b, a
/// mobile-CPU/turbo effect), and we route to the asm core only at `L >= 32`
/// (≥2048-bit: RSA/Paillier/VDF), where the win is robust. Every smaller
/// modulus uses the portable CIOS — critically our pairing fields
/// (`bn254` Fp = 254b → L=4, `bls12_381` Fp = 381b → L=6), which MUST stay
/// portable. The asm core is still correct at every L (the differential proves
/// it) — this is purely a speed dispatch.
pub const asm_min_limbs: usize = 32;

/// Small-L cutoff for the *portable dedicated square* (`montSqrCios`). The
/// square saves ~½L² limb products vs a general multiply, but the SOS structure
/// (a full 2L-word product buffer swept once more for the Montgomery reduce)
/// carries a fixed per-op overhead that, at very small L, cancels the product
/// saving. Measured on this repo's host (Kaby Lake, ReleaseFast): the portable
/// square is ~1.20× faster than the portable multiply at L=8, ~1.15× at L=16,
/// ~1.23× at L=32/64 — but a hair SLOWER at L=4. So the dedicated square is used
/// only at `L >= sqr_min_limbs`; smaller moduli (incl. the pairing-field sizes
/// `bn254` L=4 / `bls12_381` L=6, and any other tiny modulus) keep squaring via
/// the general `montMulCios`, guaranteeing no regression. Like `asm_min_limbs`
/// this is a pure speed dispatch — `montSqrCios` is correct at every L (the
/// squaring differential proves it against `montMulCios(a,a)`).
pub const sqr_min_limbs: usize = 8;

/// A modulus + its Montgomery constants, parameterized by an upper bound on the
/// modulus bit-width. `L = ceil(max_bits/64)` full 2^64 limbs; the modulus
/// occupies exactly `L` limbs (leading zero limbs are allowed as long as the
/// value is odd and ≥ 3).
pub fn Modint(comptime max_bits: comptime_int) type {
    comptime std.debug.assert(max_bits >= 8);
    return struct {
        const Self = @This();

        /// Error set surfaced by this type's byte-loader constructors
        /// (`fromBytesBE`/`elementFromBytesBE`). Re-exported from the
        /// module-level `Error` so `Modint(bits).Error` resolves — the free
        /// `elemFromBytesBE` helper refers to it as `M.Error`, and without
        /// this alias those public loaders do not compile when instantiated
        /// (a latent bug: montint's own tests never exercised them).
        pub const Error = @import("montint.zig").Error;

        /// Number of full 2^64 limbs.
        pub const L: usize = (max_bits + 63) / 64;
        /// Byte width of a serialized element.
        pub const encoded_bytes: usize = (max_bits + 7) / 8;
        /// A field/ring element: `L` little-endian 2^64 limbs.
        pub const Elem = [L]u64;

        /// The odd modulus (little-endian, `L` limbs).
        m: Elem,
        /// `-m[0]⁻¹ mod 2^64`, the CIOS reduction constant.
        n0inv: u64,
        /// `R² mod m` where `R = 2^(64·L)` — used by `toMontgomery`.
        r2: Elem,
        /// `R mod m` — the value `1` in the Montgomery domain.
        one_mont: Elem,

        // ── construction ────────────────────────────────────────────────────

        /// Build a modulus from a big-endian byte string. Rejects even moduli,
        /// moduli < 3, and values that do not fit in `max_bits`.
        pub fn fromBytesBE(bytes: []const u8) Self.Error!Self {
            const v = try elemFromBytesBE(Self, bytes);
            return fromElem(v);
        }

        /// Build a modulus from an `L`-limb little-endian value.
        pub fn fromElem(v: Elem) Self.Error!Self {
            if (v[0] & 1 == 0) return error.EvenModulus;
            // reject < 3 (only limb 0, value 1) — 1 is not a valid modulus.
            var nonzero_high: u64 = 0;
            for (v[1..]) |w| nonzero_high |= w;
            if (nonzero_high == 0 and v[0] < 3) return error.ModulusTooSmall;

            var self: Self = .{
                .m = v,
                .n0inv = negInvMod2_64(v[0]),
                .r2 = undefined,
                .one_mont = undefined,
            };
            self.computeConstants();
            return self;
        }

        /// Actual bit-length of the modulus.
        pub fn bits(self: *const Self) usize {
            var i: usize = L;
            while (i > 0) : (i -= 1) {
                if (self.m[i - 1] != 0) {
                    return (i - 1) * 64 + (64 - @clz(self.m[i - 1]));
                }
            }
            return 0;
        }

        // Compute R mod m (= one_mont) and R² mod m (= r2) by repeated doubling
        // mod m. R² needs 128·L doublings; obviously-correct and cheap at setup.
        fn computeConstants(self: *Self) void {
            // acc = 1, double 64·L times -> 2^(64L) mod m = R mod m.
            var acc = std.mem.zeroes(Elem);
            acc[0] = 1;
            var i: usize = 0;
            while (i < 64 * L) : (i += 1) self.doubleMod(&acc);
            self.one_mont = acc;
            // continue another 64·L doublings -> 2^(128L) mod m = R² mod m.
            while (i < 128 * L) : (i += 1) self.doubleMod(&acc);
            self.r2 = acc;
        }

        // acc = 2·acc mod m, with acc < m on entry and exit. CT-shaped.
        fn doubleMod(self: *const Self, acc: *Elem) void {
            var top: u64 = 0;
            for (acc) |*w| {
                const nw = (w.* << 1) | top;
                top = w.* >> 63;
                w.* = nw;
            }
            condSubTop(acc, top, &self.m);
        }

        // ── domain conversion ───────────────────────────────────────────────

        /// Reduce a big-endian byte string into a normal-domain element `< m`.
        pub fn elementFromBytesBE(self: *const Self, bytes: []const u8) Self.Error!Elem {
            const v = try elemFromBytesBE(Self, bytes);
            if (limbs.cmp(&v, &self.m) != .lt) return error.NonCanonical;
            return v;
        }

        /// Serialize a normal-domain element to a big-endian byte string.
        pub fn toBytesBE(self: *const Self, v: *const Elem, out: []u8) void {
            _ = self;
            std.debug.assert(out.len == encoded_bytes);
            var bit: usize = 0;
            var oi: usize = out.len;
            @memset(out, 0);
            while (bit < max_bits) : (bit += 8) {
                const limb = bit / 64;
                const shift: u6 = @intCast(bit % 64);
                oi -= 1;
                out[oi] = @truncate(v[limb] >> shift);
            }
        }

        /// `a` (normal domain) → Montgomery domain (`a·R mod m`).
        pub fn toMontgomery(self: *const Self, a: *const Elem) Elem {
            return self.montMul(a, &self.r2);
        }

        /// `a` (Montgomery domain) → normal domain (`a·R⁻¹ mod m`).
        pub fn fromMontgomery(self: *const Self, a_mont: *const Elem) Elem {
            var one = std.mem.zeroes(Elem);
            one[0] = 1;
            return self.montMul(a_mont, &one);
        }

        // ── modular arithmetic ──────────────────────────────────────────────

        /// `(a + b) mod m`, domain-agnostic (both operands same domain).
        pub fn add(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            var out = a.*;
            const carry = limbs.addInto(&out, b);
            condSubTop(&out, carry, &self.m);
            return out;
        }

        /// `(a − b) mod m`, domain-agnostic (both operands same domain).
        pub fn sub(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            var out = a.*;
            const borrow = limbs.subInto(&out, b);
            // if it underflowed, add m back (CT).
            var addm = self.m;
            const mask: u64 = 0 -% @as(u64, borrow);
            for (&addm) |*w| w.* &= mask;
            _ = limbs.addInto(&out, &addm);
            return out;
        }

        /// `(a · b) mod m` in the NORMAL domain (the user-facing modmul the KAT
        /// pins). Costs two Montgomery multiplies: `montMul(toMont(a), b)`.
        pub fn mul(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            const a_mont = self.toMontgomery(a);
            return self.montMul(&a_mont, b);
        }

        /// Montgomery multiply `z = a·b·R⁻¹ mod m`. Dispatches to the gated
        /// amd64 core when active, else the portable CIOS oracle. Both operands
        /// and the result are `L` full-limb values; the result is fully reduced
        /// (`z < m`).
        pub fn montMul(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            var z: Elem = undefined;
            // Small-L cutoff: asm only pays off for large moduli (see
            // `asm_min_limbs`); pairing fields (L=4/6) stay portable.
            if (comptime asm_active and L >= asm_min_limbs) {
                asm_core.montMul(&z, a, b, &self.m, self.n0inv);
            } else {
                z = self.montMulCios(a, b);
            }
            return z;
        }

        /// True iff `montMul` on this `Modint` routes to the amd64 asm core
        /// (asm available+on AND the modulus is large enough to clear the
        /// `asm_min_limbs` small-L cutoff). Used by the bench harness.
        pub fn dispatchesToAsm() bool {
            return asm_active and L >= asm_min_limbs;
        }

        /// Montgomery squaring `z = a²·R⁻¹ mod m`. A dedicated square is ~1.5×
        /// cheaper than a general multiply because the cross-product half
        /// `a[i]·a[j]` (i<j) is computed once and doubled instead of twice.
        ///
        /// Dispatch mirrors `montMul`:
        ///   * `L >= asm_min_limbs` with the asm core active → the DEDICATED
        ///     asm square `asm_core.montSqr` (SOS with `MULX/ADCX/ADOX` rows —
        ///     each off-diagonal product computed once and doubled; measured
        ///     faster than the asm `montMul(a,a)` it replaced at L=32/64, see
        ///     SPEC "Benchmarks"). Covers rsa-4096, paillier, vdf,
        ///     threshold_ecdsa on amd64 — and modexp's square steps, which are
        ///     ~5/6 of `powMont`'s multiplies.
        ///   * else `L >= sqr_min_limbs` → portable `montSqrCios`, the dedicated
        ///     square (rsa-2048 CRT at L=16, and every `L >= asm_min_limbs`
        ///     modulus on non-amd64 targets / OpenWRT).
        ///   * else (tiny L, incl. the pairing-field sizes) → `montMulCios(a,a)`,
        ///     where the general multiply is as fast or faster.
        pub fn montSqr(self: *const Self, a: *const Elem) Elem {
            if (comptime asm_active and L >= asm_min_limbs) {
                var z: Elem = undefined;
                var scratch: [2 * L]u64 = undefined;
                asm_core.montSqr(&z, a, &self.m, self.n0inv, &scratch);
                return z;
            }
            if (comptime L >= sqr_min_limbs) return self.montSqrCios(a);
            return self.montMulCios(a, a);
        }

        /// The PORTABLE constant-time dedicated Montgomery squaring — the
        /// square-optimized analogue of `montMulCios`, and its differential
        /// oracle is `montMulCios(a, a)` (proven correct there).
        ///
        /// Structure (SOS: separated square, then Montgomery-reduce):
        ///   1. **Cross products** — `A = Σ_{i<j} a[i]·a[j]·B^(i+j)` (each
        ///      off-diagonal product computed ONCE; this is the ~½L² saving).
        ///   2. **Double** — `A ← 2·A` (a 1-bit left shift over all 2L words;
        ///      `2·cross < B^(2L)` so no word overflows out the top).
        ///   3. **Diagonal** — `A ← A + Σ_i a[i]²·B^(2i)`, giving `A = a²` in
        ///      full 2L-word form.
        ///   4. **Montgomery reduce** — `z = A·R⁻¹ mod m` via the word-serial
        ///      REDC, with the per-word carry threaded through a single scalar
        ///      `cc` (the carry out of column `i+L` at step `i` is exactly the
        ///      carry *into* column `(i+1)+L` at step `i+1`, so it needs no
        ///      variable-length ripple — keeping the reduction constant-time).
        ///
        /// Constant-time: every loop bound is the PUBLIC limb count `L`; the
        /// symmetry (which products are halved) is structural, not
        /// value-dependent; the final reduction is the same masked `condSubTop`.
        /// No secret-dependent branch, index, or early exit.
        pub fn montSqrCios(self: *const Self, a: *const Elem) Elem {
            const m = &self.m;
            // A holds the full 2L-word square across all four phases.
            var A = [_]u64{0} ** (2 * L);

            // ── 1. cross products: A = Σ_{i<j} a[i]·a[j]·B^(i+j) ──
            var i: usize = 0;
            while (i < L) : (i += 1) {
                var carry: u64 = 0;
                var j: usize = i + 1;
                while (j < L) : (j += 1) {
                    const p = @as(u128, a[i]) * @as(u128, a[j]) + A[i + j] + carry;
                    A[i + j] = @truncate(p);
                    carry = @truncate(p >> 64);
                }
                // A[i+L] is still 0 here (nothing has reached it); for i=L-1 the
                // inner loop is empty and carry is 0.
                A[i + L] = carry;
            }

            // ── 2. double: A ← 2·A ──
            var top: u64 = 0;
            for (&A) |*w| {
                const nw = (w.* << 1) | top;
                top = w.* >> 63;
                w.* = nw;
            }
            // top == 0: 2·cross < B^(2L) because cross < B^(2L-1).

            // ── 3. diagonal: A ← A + Σ_i a[i]²·B^(2i) ──
            var dcarry: u64 = 0;
            i = 0;
            while (i < L) : (i += 1) {
                const sq = @as(u128, a[i]) * @as(u128, a[i]);
                const p1 = @as(u128, A[2 * i]) + @as(u64, @truncate(sq)) + dcarry;
                A[2 * i] = @truncate(p1);
                const p2 = @as(u128, A[2 * i + 1]) + @as(u64, @truncate(sq >> 64)) + @as(u64, @truncate(p1 >> 64));
                A[2 * i + 1] = @truncate(p2);
                dcarry = @truncate(p2 >> 64); // ≤ 1; flows to A[2(i+1)] next round
            }
            // dcarry == 0 here: a² < B^(2L) fits exactly in 2L words.

            // ── 4. Montgomery reduce: z = A·R⁻¹ mod m ──
            var cc: u64 = 0; // carry into column i+L, carried between steps
            i = 0;
            while (i < L) : (i += 1) {
                const u = A[i] *% self.n0inv;
                var carry: u64 = 0;
                var j: usize = 0;
                while (j < L) : (j += 1) {
                    const p = @as(u128, u) * @as(u128, m[j]) + A[i + j] + carry;
                    A[i + j] = @truncate(p);
                    carry = @truncate(p >> 64);
                }
                // Column i+L collects the inner-loop carry plus the pending cc
                // from step i-1 (which is precisely the carry out of column
                // (i-1)+L = i+L-1). The carry out here (0/1) becomes the next
                // step's cc, added at column (i+1)+L — no variable ripple.
                const s = @as(u128, A[i + L]) + carry + cc;
                A[i + L] = @truncate(s);
                cc = @truncate(s >> 64);
            }
            // result = A[L..2L] with top word cc (0/1 since A = a² < R·m).
            var z: Elem = undefined;
            @memcpy(&z, A[L .. 2 * L]);
            condSubTop(&z, cc, m);
            return z;
        }

        /// The PORTABLE constant-time CIOS Montgomery multiply — the oracle.
        /// Coarsely Integrated Operand Scanning (Koç et al., Fig. 6), radix
        /// 2^64, with `u128` widening products. No secret-dependent branch,
        /// index, or early exit; the final reduction is a constant-time
        /// conditional subtract.
        pub fn montMulCios(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            const m = &self.m;
            // t holds L+2 words across the interleaved multiply/reduce passes.
            var t = [_]u64{0} ** (L + 2);
            var i: usize = 0;
            while (i < L) : (i += 1) {
                // t += a * b[i]
                var carry: u64 = 0;
                var j: usize = 0;
                while (j < L) : (j += 1) {
                    const p = @as(u128, a[j]) * @as(u128, b[i]) + t[j] + carry;
                    t[j] = @truncate(p);
                    carry = @truncate(p >> 64);
                }
                const s = @as(u128, t[L]) + carry;
                t[L] = @truncate(s);
                t[L + 1] = @truncate(s >> 64);

                // u = t[0] * n0inv mod 2^64 ; t = (t + u*m) / 2^64
                const u = t[0] *% self.n0inv;
                const p0 = @as(u128, u) * @as(u128, m[0]) + t[0];
                var carry2: u64 = @truncate(p0 >> 64); // low word is 0 by construction
                j = 1;
                while (j < L) : (j += 1) {
                    const p = @as(u128, u) * @as(u128, m[j]) + t[j] + carry2;
                    t[j - 1] = @truncate(p);
                    carry2 = @truncate(p >> 64);
                }
                const s2 = @as(u128, t[L]) + carry2;
                t[L - 1] = @truncate(s2);
                t[L] = t[L + 1] +% @as(u64, @truncate(s2 >> 64));
            }
            // result = t[0..L] with possible top word t[L] (0 or 1); reduce.
            var z: Elem = undefined;
            @memcpy(&z, t[0..L]);
            condSubTop(&z, t[L], m);
            return z;
        }

        // ── modular exponentiation ──────────────────────────────────────────

        /// `base^exp mod m` (normal domain in and out), constant-time in the
        /// exponent VALUE: fixed 5-bit window, every window does a multiply
        /// (digit 0 multiplies by `1`), the table gather is a branchless CT
        /// select over all 32 entries, and all `L·64` exponent bits are always
        /// processed. This is the analogue of the `ff` secret-modexp path and
        /// the guarantee the `rsa`/`paillier` audits rely on.
        ///
        /// `exp` is an `L`-limb little-endian value.
        pub fn powMont(self: *const Self, base: *const Elem, exp: *const Elem) Elem {
            const w: usize = 5;
            const table_len: usize = 1 << w;

            const base_mont = self.toMontgomery(base);
            // table[k] = base^k in the Montgomery domain.
            var table: [table_len]Elem = undefined;
            table[0] = self.one_mont;
            table[1] = base_mont;
            var k: usize = 2;
            while (k < table_len) : (k += 1) {
                table[k] = self.montMul(&table[k - 1], &base_mont);
            }

            var acc = self.one_mont;
            const total_bits = L * 64;
            // number of windows, MSB-aligned (top window may be partly zero).
            const nwin = (total_bits + w - 1) / w;
            var win: usize = nwin;
            while (win > 0) {
                win -= 1;
                // square w times (no-op on the very first, acc == 1).
                var s: usize = 0;
                while (s < w) : (s += 1) acc = self.montSqr(&acc);
                const digit = getBits(exp, win * w, w);
                // Constant-time gather of table[digit]: a branchless masked
                // linear scan over ALL `table_len` entries. The per-entry mask
                // is laundered through `blackBox` so the optimizer cannot
                // recover "pick the matching entry" and lower it to a
                // secret-indexed jump table (see `blackBox`). Every entry is
                // read and blended unconditionally, in constant work.
                var g = std.mem.zeroes(Elem);
                var idx: usize = 0;
                while (idx < table_len) : (idx += 1) {
                    const mask = blackBox(0 -% @as(u64, @intFromBool(idx == digit)));
                    for (&g, &table[idx]) |*gl, tl| gl.* = (tl & mask) | (gl.* & ~mask);
                }
                acc = self.montMul(&acc, &g);
            }
            return self.fromMontgomery(&acc);
        }

        // ── internal CT helpers ─────────────────────────────────────────────

        // Optimization barrier: launder a value through an (empty) inline-asm
        // so LLVM loses all range/equality knowledge about it. Used on the
        // per-entry select mask in the `powMont` window gather: without it the
        // optimizer recognises the "select the one entry where idx == digit"
        // masked scan and lowers it to a secret-indexed jump table
        // (`jmp *tbl(,digit,8)`), a real timing/BTB + memory-access-pattern
        // leak of the secret exponent. Laundering the mask forces the branchless
        // linear scan to survive — all 2^w entries are touched unconditionally
        // (verified by disassembly). No-op at runtime (empty asm template).
        inline fn blackBox(x: u64) u64 {
            return asm volatile (""
                : [ret] "=r" (-> u64),
                : [x] "0" (x),
            );
        }

        // Constant-time conditional subtract of `m` from the (L+1)-word value
        // (`v` low L words, `top` the carry word 0/1). Subtracts m iff the full
        // value ≥ m. `v < 2m` on entry, so `top ≤ 1` and the result is `< m`.
        fn condSubTop(v: *Elem, top: u64, m: *const Elem) void {
            var diff: Elem = undefined;
            var borrow: u1 = 0;
            for (&diff, v, m) |*d, vi, mi| {
                const s = @subWithOverflow(vi, mi);
                const s2 = @subWithOverflow(s[0], borrow);
                d.* = s2[0];
                borrow = s[1] | s2[1];
            }
            // full value ≥ m  ⟺  no underflow when subtracting borrow from top.
            const under = @subWithOverflow(top, borrow)[1]; // 1 ⇒ value < m
            const keep_orig: u64 = 0 -% @as(u64, under);
            for (v, &diff) |*vi, di| {
                vi.* = (vi.* & keep_orig) | (di & ~keep_orig);
            }
        }

        // Extract `count` (≤ 8) bits from an L-limb value starting at bit `off`
        // (bits at/above `L·64` read as 0). Not secret-branching on the value.
        fn getBits(v: *const Elem, off: usize, count: usize) usize {
            var out: usize = 0;
            var b: usize = 0;
            while (b < count) : (b += 1) {
                const pos = off + b;
                var bit: u1 = 0;
                if (pos < L * 64) {
                    const limb = pos / 64;
                    const sh: u6 = @intCast(pos % 64);
                    bit = @truncate(v[limb] >> sh);
                }
                out |= @as(usize, bit) << @intCast(b);
            }
            return out;
        }
    };
}

// ── free helpers ────────────────────────────────────────────────────────────

/// `-x⁻¹ mod 2^64` for odd `x`, via Newton–Hensel doubling (6 steps: correct
/// bits double 1→2→4→…→64).
pub fn negInvMod2_64(x: u64) u64 {
    var y: u64 = 1; // x⁻¹ mod 2 (x is odd)
    inline for (0..6) |_| y = y *% (2 -% x *% y);
    return 0 -% y; // -(x⁻¹)
}

fn elemFromBytesBE(comptime M: type, bytes: []const u8) M.Error!M.Elem {
    var v = std.mem.zeroes(M.Elem);
    if (bytes.len == 0) return v;
    var bit: usize = 0;
    var i: usize = bytes.len;
    while (i > 0) : (bit += 8) {
        i -= 1;
        const byte = bytes[i];
        if (byte == 0) continue;
        const limb = bit / 64;
        const sh: u6 = @intCast(bit % 64);
        if (limb >= M.L) return error.Overflow;
        const wide = @as(u128, byte) << sh;
        v[limb] |= @as(u64, @truncate(wide));
        if (sh != 0 and (wide >> 64) != 0) {
            if (limb + 1 >= M.L) return error.Overflow;
            v[limb + 1] |= @as(u64, @truncate(wide >> 64));
        }
    }
    return v;
}

test "Modint.bits reports the exact bit-length of the modulus, not the limb width" {
    const M = Modint(256);
    // A 1-limb-ish modulus with a nonzero high (3rd) limb: only that limb's
    // own bit-length should count, not `L * 64`.
    var mv = std.mem.zeroes(M.Elem);
    mv[0] = 1; // odd
    mv[2] = 0b101; // top set bit is bit 2 of limb index 2
    const m = try M.fromElem(mv);
    try std.testing.expectEqual(@as(usize, 2 * 64 + 3), m.bits());

    // A modulus that fits entirely in the low limb.
    var mv2 = std.mem.zeroes(M.Elem);
    mv2[0] = 0b1011; // bits 0..3, top bit is bit 3
    const m2 = try M.fromElem(mv2);
    try std.testing.expectEqual(@as(usize, 4), m2.bits());

    // The all-ones-low-limb modulus: exactly 64 bits.
    var mv3 = std.mem.zeroes(M.Elem);
    mv3[0] = 0xffff_ffff_ffff_ffff;
    const m3 = try M.fromElem(mv3);
    try std.testing.expectEqual(@as(usize, 64), m3.bits());
}

test "negInvMod2_64: m·(-m⁻¹) ≡ -1 mod 2^64" {
    for ([_]u64{ 3, 5, 0xffff_ffff_ffff_ffff, 0x1234_5678_9abc_def1 }) |m| {
        const ni = negInvMod2_64(m);
        try std.testing.expectEqual(@as(u64, 0), m *% ni +% 1);
    }
}

test "public byte loaders instantiate and round-trip (regression: Modint.Error alias)" {
    // Instantiating `fromBytesBE`/`elementFromBytesBE` forces `M.Error` to
    // resolve; before the `Modint.Error` alias was added these did not compile
    // at all (montint's other tests build moduli via `fromElem`, never the
    // byte loaders, so the missing alias was latent). This test both pins the
    // fix and checks the loaders' arithmetic against `elemFromBytesBE`.
    const M = Modint(256);
    // Odd 128-bit-ish modulus with a nonzero high limb (spans >1 limb).
    const m_be = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const mod: M.Error!M = M.fromBytesBE(&m_be);
    const modulus = try mod;

    // A reduced element loaded from bytes; must equal the branch-clean loader
    // and survive a Montgomery round trip.
    const a_be = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33 };
    const a: M.Error!M.Elem = modulus.elementFromBytesBE(&a_be);
    const a_elem = try a;
    const a_mont = modulus.toMontgomery(&a_elem);
    const a_back = modulus.fromMontgomery(&a_mont);
    try std.testing.expect(std.mem.eql(u64, &a_elem, &a_back));

    // The byte loaders' error set must reject an even modulus.
    try std.testing.expectError(error.EvenModulus, M.fromBytesBE(&[_]u8{0x02}));
    // A value >= m is non-canonical.
    try std.testing.expectError(error.NonCanonical, modulus.elementFromBytesBE(&m_be));
}

// ── fuzz: the byte loaders never panic on arbitrary bytes ─────────────────
//
// `fromBytesBE` builds a modulus straight from a caller-supplied big-endian
// byte string (an RSA/Paillier N, a VDF group order — every real caller
// sources this from a certificate, a config file, or a peer, none of them
// trusted to hand back a well-formed odd modulus). `elementFromBytesBE`
// reduces an arbitrary byte string against an already-validated modulus
// (an operand read off the wire). Both were the exact functions the
// regression test above pins as "never previously exercised at all" (the
// missing `Self.Error` alias compiled-error was latent precisely because
// nothing called them) — the natural next gap being no adversarial-input
// coverage either.

test "fuzz: fromBytesBE never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzFromBytesBE, .{});
}

fn fuzzFromBytesBE(_: void, smith: *std.testing.Smith) !void {
    const M = Modint(256);
    var buf: [48]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = M.fromBytesBE(buf[0..len]) catch {};
}

test "fuzz: elementFromBytesBE never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzElementFromBytesBE, .{});
}

fn fuzzElementFromBytesBE(_: void, smith: *std.testing.Smith) !void {
    const M = Modint(256);
    // A fixed, already-validated modulus — the byte loader under test is
    // `elementFromBytesBE`, not modulus construction (covered separately
    // above); the two must not be conflated in one harness.
    const m_be = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const modulus = M.fromBytesBE(&m_be) catch unreachable;

    var buf: [48]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = modulus.elementFromBytesBE(buf[0..len]) catch {};
}
