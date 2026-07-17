// SPDX-License-Identifier: MIT

//! bfv — the BFV leveled homomorphic-encryption scheme over the (real,
//! ungated) RNS ring `R_q = Z_q[X]/(X^N+1)` this module ships in Part 1.
//!
//! Scheme (Fan-Vercauteren 2012, "Somewhat Practical Fully Homomorphic
//! Encryption", IACR ePrint 2012/144; parameter/RNS shape follows Microsoft
//! SEAL's BFV): a secret key `s` (small), a public key `(p0,p1)=(-(a·s+e), a)`,
//! ciphertexts that decrypt via `⌊t/q·(c0+c1·s)⌉ mod t`. Plaintext `m∈R_t` is
//! scaled by `Δ=⌊q/t⌋` on encryption. HomAdd is component-wise; HomMul tensors
//! two 2-element ciphertexts into a 3-element one, rescales by `t/q`, and
//! **relinearises** back to 2 elements with an evaluation (relin) key.
//!
//! ## Status — Parts 1–3 are REAL (the full leveled scheme):
//!   - **REAL (Part 1):** the `SecretKey`/`PublicKey`/`RelinKey`/`Ciphertext`
//!     types, `Ciphertext.add`/`sub` (pure ring ops, not noise-sensitive),
//!     and `numComponents`. (Byte codecs for these types are a deferred
//!     backlog item — see `SPEC.md`.)
//!   - **REAL (Part 2, Opus — `scheme_core_implemented`):** `keyGen`,
//!     `encrypt`, `decrypt` — textbook RLWE; the `Δ`-scale decrypt is anchored
//!     by a deterministic noiseless-ciphertext KAT + the enc/dec round-trip and
//!     homomorphic-add end-to-end tests.
//!   - **REAL (Part 3, Fable — `fable_core_implemented`):** `mul` (exact
//!     integer tensor + `⌊t/q·…⌉` rescale), `genRelinKey`/`relinearize`
//!     (base-`w` gadget key-switch for `s²`), `noiseBudget` — the
//!     noise-management core. Anchored by the mul+relin and multiply-DEPTH
//!     end-to-end tests on `params.test_mul`, whose worst-case noise ledger
//!     (params.zig) makes depth-2 correctness a guarantee, not a
//!     probabilistic pass. Exact-reconstruction tensor path only (toy
//!     moduli); the fast BEHZ/HPS RNS base-conversion multiply is the
//!     deferred security-grade increment.
//!
//! Randomness is caller-supplied (`std.Random`, frost/bbs-style) so the module
//! stays `platform = .any` and KATs are reproducible.

const std = @import("std");
const params = @import("params.zig");
const ring = @import("ring.zig");
const encode = @import("encode.zig");
const gate = @import("gate.zig");
const ma = @import("modarith.zig");
const rns = @import("rns.zig");

/// `Bfv(P)` — a BFV instance for the compile-time-fixed parameter set `P`.
pub fn Bfv(comptime P: params.Params) type {
    const N = P.n;
    const L = P.primes.len;
    // Materialise the prime chain as a comptime array for the ring ops.
    const primes: [L]u64 = blk: {
        var a: [L]u64 = undefined;
        for (0..L) |i| a[i] = P.primes[i];
        break :blk a;
    };

    return struct {
        const Self = @This();
        pub const parameters = P;
        pub const degree = N;
        pub const num_primes = L;
        pub const Ring = ring.RnsPoly(N, L);
        pub const Engine = ring.RnsPoly(N, L).Engine;
        pub const Plaintext = encode.Plaintext(N);

        /// Full ciphertext modulus `q = ∏ q_i` as an integer (fits `u128` for
        /// the KAT/toy parameter sets; production RNS never materialises it).
        pub const q_product: u128 = blk: {
            var m: u128 = 1;
            for (primes) |p| m *= p;
            break :blk m;
        };
        /// The BFV scaling factor `Δ = ⌊q/t⌋` (plaintext lives in the high bits).
        pub const delta: u128 = q_product / P.t;

        /// Relinearisation gadget base `w = 2^relin_base_log2` (Part 3).
        pub const relin_base_log2: u7 = 8;
        pub const relin_base: u64 = 1 << relin_base_log2;
        /// Number of base-`w` digits covering `q`: `w^relin_digits ≥ q` and
        /// `w^(relin_digits−1) < q` (so every `w^i` used is a `[0,q)` scalar).
        pub const relin_digits: usize = blk: {
            var k: usize = 0;
            var m: u128 = q_product;
            while (m > 0) : (k += 1) m >>= relin_base_log2;
            break :blk k;
        };

        comptime {
            // Exact-tensor width guard for `mul`: the rounding numerator
            // `|2·t·T + q|` with `|T| ≤ N·(q/2)²` must fit in i256.
            const q_bits = 128 - @clz(q_product);
            const n_bits = 64 - @clz(@as(u64, N));
            const t_bits = 64 - @clz(P.t);
            if (2 * q_bits + n_bits + t_bits + 2 > 255)
                @compileError("bfv: parameter set too large for the exact-tensor multiply path");
        }

        /// The `L` per-prime NTT engines + the prime chain, built once.
        engines: [L]Engine,
        primes: [L]u64,

        pub const SecretKey = struct { s: Ring };
        pub const PublicKey = struct { p0: Ring, p1: Ring };
        pub const KeyPair = struct { sk: SecretKey, pk: PublicKey };

        /// Relinearisation / evaluation key: a base-`w` gadget key-switching
        /// key for `s²` (layout finalised in Part 3, as Part 1 announced).
        /// Row `i` is a pseudo-encryption of `w^i·s²` under `s`:
        /// `b[i] = −(a[i]·s + e_i) + w^i·s²`, so `b[i] + a[i]·s = w^i·s² − e_i`.
        pub const RelinKey = struct {
            b: [relin_digits]Ring,
            a: [relin_digits]Ring,
        };

        /// A BFV ciphertext: 2 components when fresh or relinearised, 3 after
        /// a multiply. `len ∈ {2,3}`.
        pub const Ciphertext = struct {
            components: [3]Ring,
            len: usize,

            pub fn numComponents(self: *const Ciphertext) usize {
                return self.len;
            }
        };

        /// Build the instance (validates `P`, builds NTT engines).
        pub fn init() !Self {
            try P.validate();
            var local = primes;
            const engines = try ring.makeEngines(N, L, &local);
            return .{ .engines = engines, .primes = primes };
        }

        // ── REAL, ungated ops ────────────────────────────────────────────────

        /// Homomorphic addition `Enc(a) ⊕ Enc(b)` — component-wise ring add.
        /// Pure `R_q` arithmetic, not noise-sensitive, so it is REAL in
        /// Part 1 (though it is only observable once `encrypt`/`decrypt` land).
        /// Both inputs must have the same component count.
        pub fn add(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == y.len);
            var out = x.*;
            for (0..x.len) |i| out.components[i].addAssign(&y.components[i], &self.primes);
            return out;
        }

        /// Homomorphic subtraction, component-wise.
        pub fn sub(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == y.len);
            var out = x.*;
            for (0..x.len) |i| out.components[i].subAssign(&y.components[i], &self.primes);
            return out;
        }

        // ── scheme core (Part 2, Opus — textbook RLWE) ───────────────────────
        //
        // Correctness anchor (SPEC.md "Anchors"): decrypt inverts the `Δ`-scale
        // exactly on a hand-constructed noiseless ciphertext (deterministic KAT,
        // independent of keyGen/encrypt); the fresh-encryption noise
        // `E = −e·u + e0 + e1·s` is bounded ≪ `Δ/2`, so the enc/dec round-trip
        // and homomorphic-add end-to-end anchors decrypt back byte-exact for
        // EVERY seed (not a probabilistic property at this depth).

        /// Sample a ternary polynomial (each coefficient uniform in `{−1,0,1}`)
        /// as a coefficient-domain ring element. Used for the secret key, the
        /// encryption randomness `u`, and the small errors `e,e0,e1` — a
        /// consistent small integer per coefficient across all RNS limbs
        /// (`−1 ↦ q_i−1`), which keeps the decrypt-noise a genuine small
        /// integer. NOT constant-time (toy parameters; see SPEC.md).
        fn sampleTernary(self: *const Self, random: std.Random) Ring {
            var out = Ring.zero(.coeff);
            for (0..N) |j| {
                const r = random.uintLessThan(u8, 3); // 0,1,2 ↦ −1,0,1
                for (0..L) |i| out.limbs[i][j] = switch (r) {
                    0 => self.primes[i] - 1, // −1
                    1 => 0,
                    else => 1,
                };
            }
            return out;
        }

        /// Sample a uniform ring element in `R_q` (each limb uniform in
        /// `[0,q_i)` — by CRT this is uniform mod `q`). Used for the public-key
        /// mask `a`.
        fn sampleUniform(self: *const Self, random: std.Random) Ring {
            var out = Ring.zero(.coeff);
            for (0..L) |i| {
                for (0..N) |j| out.limbs[i][j] = random.uintLessThan(u64, self.primes[i]);
            }
            return out;
        }

        /// `Δ·m` as a coefficient-domain ring element. `Δ·m_j < q`, so the
        /// per-limb `(Δ mod q_i)·(m_j mod q_i) mod q_i` equals the residue of
        /// the integer `Δ·m_j` (no wrap).
        fn scaledPlaintext(self: *const Self, pt: *const Plaintext) Ring {
            var out = Ring.zero(.coeff);
            for (0..L) |i| {
                const qi = self.primes[i];
                const delta_i: u64 = @intCast(delta % qi);
                for (0..N) |j| out.limbs[i][j] = ma.mulMod(delta_i, pt.coeffs[j] % qi, qi);
            }
            return out;
        }

        /// Generate a BFV keypair. `random` supplies the secret (ternary) key,
        /// the uniform public-key mask `a`, and the small error `e`.
        /// `pk = (p0, p1) = (−(a·s + e), a)`.
        pub fn keyGen(self: *const Self, random: std.Random) KeyPair {
            const s = self.sampleTernary(random);
            const a = self.sampleUniform(random);
            const e = self.sampleTernary(random);
            var p0 = a.mul(&s, &self.engines, &self.primes); // a·s
            p0.addAssign(&e, &self.primes); // a·s + e
            p0.negate(&self.primes); // −(a·s + e)
            return .{ .sk = .{ .s = s }, .pk = .{ .p0 = p0, .p1 = a } };
        }

        /// Encrypt `pt ∈ R_t`: `c0 = Δ·m + p0·u + e0`, `c1 = p1·u + e1`,
        /// `Δ = ⌊q/t⌋`. `random` supplies the ternary `u,e0,e1`.
        pub fn encrypt(self: *const Self, pk: *const PublicKey, pt: *const Plaintext, random: std.Random) Ciphertext {
            const u = self.sampleTernary(random);
            const e0 = self.sampleTernary(random);
            const e1 = self.sampleTernary(random);
            var c0 = self.scaledPlaintext(pt); // Δ·m
            var p0u = pk.p0.mul(&u, &self.engines, &self.primes);
            c0.addAssign(&p0u, &self.primes); // + p0·u
            c0.addAssign(&e0, &self.primes); // + e0
            var c1 = pk.p1.mul(&u, &self.engines, &self.primes);
            c1.addAssign(&e1, &self.primes); // p1·u + e1
            return .{ .components = .{ c0, c1, Ring.zero(.coeff) }, .len = 2 };
        }

        /// Decrypt: `⌊t/q·(Σ_i c_i·s^i)⌉ mod t`, coefficient-wise. The phase
        /// `Σ_i c_i·s^i = Δ·m + E` is reconstructed exactly per coefficient via
        /// CRT, then rescaled with round-half-up
        /// `⌊(2·t·v + q)/(2q)⌋ mod t`. Handles `len ∈ {2,3}` (a 3-component
        /// ciphertext — post-multiply — needs the `c2·s²` term).
        pub fn decrypt(self: *const Self, sk: *const SecretKey, ct: *const Ciphertext) Plaintext {
            // phase = Σ_i c_i·s^i in R_q (c0 + c1·s [+ c2·s² …]).
            var acc = ct.components[0];
            if (ct.len >= 2) {
                var spow = sk.s; // s^1
                var term = ct.components[1].mul(&spow, &self.engines, &self.primes);
                acc.addAssign(&term, &self.primes);
                var i: usize = 2;
                while (i < ct.len) : (i += 1) {
                    spow = spow.mul(&sk.s, &self.engines, &self.primes); // s^i
                    var t2 = ct.components[i].mul(&spow, &self.engines, &self.primes);
                    acc.addAssign(&t2, &self.primes);
                }
            }
            // ⌊t/q · phase⌉ mod t, coefficient-wise, via exact CRT reconstruction.
            const basis = rns.Basis{ .primes = self.primes[0..] };
            var out = Plaintext.zero(P.t);
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = acc.limbs[i][j];
                const v = basis.reconstruct(&res); // in [0, q)
                // round(t·v/q) = ⌊(2·t·v + q) / (2q)⌋ ; then reduce mod t.
                const rounded = (2 * @as(u128, P.t) * v + q_product) / (2 * q_product);
                out.coeffs[j] = @intCast(rounded % @as(u128, P.t));
            }
            return out;
        }

        // ── Fable core (Part 3 — noise management) ───────────────────────────
        //
        // Correctness story (SPEC.md "Part-3 noise budget"): write the exact
        // integer identity `ct(s) = c0 + c1·s = Δ·m + v + q·r` (centered
        // representatives, ‖r‖ ≤ (N+3)/2). Then
        //   ct1(s)·ct2(s) = Δ²m1m2 + Δ(m1v2+m2v1) + v1v2
        //                 + q·[r1(Δm2+v2) + r2(Δm1+v1)] + q²·r1r2 ,
        // and multiplying by t/q (with tΔ = q − r_t, r_t = q mod t) gives
        //   (t/q)·ct1(s)·ct2(s) ≡ Δ·[m1m2]_t + v_mult   (mod q),
        //   v_mult = (m1v2+m2v1) + t·(r1v2+r2v1)  [dominant]
        //          − r_t·(r1m2+r2m1 + m1m2-carries + …) + (t/q)·v1v2 ,
        // i.e. the t/q rescale CANCELS one Δ so the product stays scaled by Δ
        // (not Δ²), and the noise grows ≈ multiplicatively (·t·N·‖r‖), NOT to
        // Δ²-scale garbage. The per-component rounding `⌊t/q·T_i⌉` adds
        // ε0+ε1·s+ε2·s² ≤ (1+N+N²)/2. CRITICALLY the tensor `T_i` must be an
        // EXACT integer product of fixed `[0,q)`-representative polynomials
        // (centered here, to halve the noise constants): rescaling a mod-q
        // ring product instead would drop `t·k_i ≢ 0 (mod q)` per component
        // and decrypt to garbage — which is why `mul` reconstructs exactly
        // instead of staying in RNS. The security-grade fast path (BEHZ/HPS
        // RNS base extension, never materialising the integer) is the
        // deferred increment (SPEC.md).

        /// Exact centered integer coefficients of a coeff-domain ring element:
        /// CRT-reconstruct each coefficient to `[0,q)`, then center into
        /// `(−q/2, q/2)`. i256 so tensor products below stay exact.
        fn centeredCoeffs(self: *const Self, r: *const Ring) [N]i256 {
            std.debug.assert(r.domain == .coeff);
            const basis = rns.Basis{ .primes = self.primes[0..] };
            const half = q_product / 2;
            var out: [N]i256 = undefined;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = r.limbs[i][j];
                const v = basis.reconstruct(&res); // [0, q)
                out[j] = if (v > half)
                    -@as(i256, @intCast(q_product - v))
                else
                    @as(i256, @intCast(v));
            }
            return out;
        }

        /// `acc += a·b mod (X^N+1)` over the integers (exact schoolbook
        /// negacyclic convolution; |terms| ≤ N·(q/2)², guarded comptime).
        fn negaMulAcc(a: *const [N]i256, b: *const [N]i256, acc: *[N]i256) void {
            for (0..N) |i| {
                for (0..N) |j| {
                    const p = a[i] * b[j];
                    const k = i + j;
                    if (k < N) acc[k] += p else acc[k - N] -= p; // X^N = −1
                }
            }
        }

        /// `⌊t/q · T⌉ mod q` per coefficient (round half up via floor
        /// division, exact for negative T), decomposed back into RNS limbs.
        fn rescaleTensor(self: *const Self, tc: *const [N]i256) Ring {
            var out = Ring.zero(.coeff);
            const qi: i256 = @intCast(q_product);
            const ti: i256 = @intCast(P.t);
            for (0..N) |j| {
                const rounded = @divFloor(2 * ti * tc[j] + qi, 2 * qi);
                const v: u128 = @intCast(@mod(rounded, qi)); // canonical [0, q)
                for (0..L) |i| out.limbs[i][j] = @intCast(v % self.primes[i]);
            }
            return out;
        }

        /// `scalar·r` for a `[0,q)` scalar, per-limb (legal in either domain).
        fn scalarMul(self: *const Self, r: *const Ring, scalar: u128) Ring {
            var out = r.*;
            for (0..L) |i| {
                const c: u64 = @intCast(scalar % self.primes[i]);
                for (&out.limbs[i]) |*x| x.* = ma.mulMod(x.*, c, self.primes[i]);
            }
            return out;
        }

        /// Generate the relinearisation key: a base-`w` gadget key-switching
        /// key for `s²`. Row `i` pseudo-encrypts `w^i·s²` under `s` with a
        /// fresh ternary error `e_i`: `(b_i, a_i) = (−(a_i·s + e_i) + w^i·s²,
        /// a_i)`. `random` supplies the uniform `a_i` and ternary `e_i`.
        pub fn genRelinKey(self: *const Self, sk: *const SecretKey, random: std.Random) RelinKey {
            const s2 = sk.s.mul(&sk.s, &self.engines, &self.primes);
            var rlk: RelinKey = undefined;
            var w_pow: u128 = 1; // w^i < q for all rows used (see relin_digits)
            for (0..relin_digits) |i| {
                const a_i = self.sampleUniform(random);
                const e_i = self.sampleTernary(random);
                var b_i = self.scalarMul(&s2, w_pow); // w^i·s²
                var mask = a_i.mul(&sk.s, &self.engines, &self.primes); // a_i·s
                mask.addAssign(&e_i, &self.primes); // + e_i
                b_i.subAssign(&mask, &self.primes); // w^i·s² − (a_i·s + e_i)
                rlk.b[i] = b_i;
                rlk.a[i] = a_i;
                w_pow = @intCast((@as(u256, w_pow) << relin_base_log2) % q_product);
            }
            return rlk;
        }

        /// Homomorphic multiply → a 3-component ciphertext (degree 2 in `s`).
        /// Tensor `(c0,c1)⊗(d0,d1) = (c0d0, c0d1+c1d0, c1d1)` computed EXACTLY
        /// over the integers (centered representatives — see the correctness
        /// note above for why a mod-q ring tensor would be silently wrong),
        /// then the `⌊t/q·…⌉` rescale per component, which keeps the plaintext
        /// scaled by `Δ` (not `Δ²`). Decrypts with `(1, s, s²)`;
        /// `relinearize` reduces it back to 2 components.
        pub fn mul(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == 2 and y.len == 2);
            const x0 = self.centeredCoeffs(&x.components[0]);
            const x1 = self.centeredCoeffs(&x.components[1]);
            const y0 = self.centeredCoeffs(&y.components[0]);
            const y1 = self.centeredCoeffs(&y.components[1]);
            var t0 = [_]i256{0} ** N;
            var t1 = [_]i256{0} ** N;
            var t2 = [_]i256{0} ** N;
            negaMulAcc(&x0, &y0, &t0);
            negaMulAcc(&x0, &y1, &t1);
            negaMulAcc(&x1, &y0, &t1);
            negaMulAcc(&x1, &y1, &t2);
            return .{ .components = .{
                self.rescaleTensor(&t0),
                self.rescaleTensor(&t1),
                self.rescaleTensor(&t2),
            }, .len = 3 };
        }

        /// Relinearise a 3-component ciphertext back to 2 via the relin key:
        /// digit-decompose `c2 = Σ_i w^i·d_i` (exact, digits in `[0,w)`), then
        /// `(c0', c1') = (c0 + Σ d_i·b_i, c1 + Σ d_i·a_i)`. Correctness:
        ///   c0' + c1'·s = c0 + c1·s + Σ d_i·(b_i + a_i·s)
        ///               = c0 + c1·s + Σ d_i·(w^i·s² − e_i)
        ///               = c0 + c1·s + c2·s² − Σ d_i·e_i ,
        /// i.e. the phase is PRESERVED up to the key-switch noise
        /// `‖Σ d_i·e_i‖ ≤ relin_digits·N·(w−1)` — the `c2·s²` term is replaced
        /// by an encryption of the same value under `s`.
        pub fn relinearize(self: *const Self, ct: *const Ciphertext, rlk: *const RelinKey) Ciphertext {
            std.debug.assert(ct.len == 3);
            const basis = rns.Basis{ .primes = self.primes[0..] };
            // Exact base-w digits of every coefficient of c2.
            var digits: [relin_digits][N]u64 = undefined;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = ct.components[2].limbs[i][j];
                var v = basis.reconstruct(&res); // [0, q)
                for (0..relin_digits) |i| {
                    digits[i][j] = @intCast(v & (relin_base - 1));
                    v >>= relin_base_log2;
                }
            }
            var c0 = ct.components[0];
            var c1 = ct.components[1];
            for (0..relin_digits) |i| {
                // d_i as a ring element: the same small integer digit per
                // coefficient across all limbs (its residues), like the
                // ternary sampler.
                var d = Ring.zero(.coeff);
                for (0..L) |l| {
                    for (0..N) |j| d.limbs[l][j] = digits[i][j] % self.primes[l];
                }
                var tb = d.mul(&rlk.b[i], &self.engines, &self.primes);
                c0.addAssign(&tb, &self.primes);
                var ta = d.mul(&rlk.a[i], &self.engines, &self.primes);
                c1.addAssign(&ta, &self.primes);
            }
            return .{ .components = .{ c0, c1, Ring.zero(.coeff) }, .len = 2 };
        }

        /// Remaining noise budget (bits) of `ct` under `sk`:
        /// `⌊log2(q / (2·‖v‖_∞))⌋` where `v = centered(phase − Δ·m)` and `m`
        /// is the decrypted plaintext; `0` == exhausted (decryption failure
        /// territory). Decryption stays exact while `t·‖v‖ + r_t·‖m‖ < q/2`,
        /// i.e. while the budget is comfortably above `log2 t`.
        pub fn noiseBudget(self: *const Self, sk: *const SecretKey, ct: *const Ciphertext) u32 {
            // phase = Σ_i c_i·s^i in R_q (same accumulation as decrypt).
            var acc = ct.components[0];
            if (ct.len >= 2) {
                var spow = sk.s;
                var term = ct.components[1].mul(&spow, &self.engines, &self.primes);
                acc.addAssign(&term, &self.primes);
                var i: usize = 2;
                while (i < ct.len) : (i += 1) {
                    spow = spow.mul(&sk.s, &self.engines, &self.primes);
                    var t2 = ct.components[i].mul(&spow, &self.engines, &self.primes);
                    acc.addAssign(&t2, &self.primes);
                }
            }
            const basis = rns.Basis{ .primes = self.primes[0..] };
            const half = q_product / 2;
            var vmax: u128 = 0;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = acc.limbs[i][j];
                const phase = basis.reconstruct(&res); // [0, q)
                // m_j exactly as decrypt recovers it (round half up, mod t).
                const rounded = (2 * @as(u128, P.t) * phase + q_product) / (2 * q_product);
                const m_j = rounded % @as(u128, P.t);
                const dm = delta * m_j; // < q (m_j ≤ t−1, Δ·(t−1) < q)
                const d = (phase + q_product - dm) % q_product;
                const v = if (d > half) q_product - d else d; // |centered|
                vmax = @max(vmax, v);
            }
            if (vmax == 0) return @intCast(std.math.log2_int(u128, q_product / 2));
            const ratio = q_product / (2 * vmax);
            if (ratio <= 1) return 0;
            return @intCast(std.math.log2_int(u128, ratio));
        }
    };
}

// ── tests: the REAL, ungated scheme surface (types + add) ─────────────────────

const testing = std.testing;

test "instance builds and exposes real ring add on ciphertext components" {
    const B = Bfv(params.test_tiny);
    const inst = try B.init();
    try testing.expectEqual(@as(usize, 8), B.degree);
    try testing.expectEqual(@as(usize, 2), B.num_primes);

    // Build two "ciphertexts" directly from ring elements (no encrypt yet) and
    // confirm `add` is exactly component-wise ring addition — a real op today.
    const primes = [_]u64{ 17, 97 };
    var a = B.Ciphertext{ .components = .{
        B.Ring.fromCoeffs(&primes, .{ [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 }, [_]u64{ 1, 1, 1, 1, 1, 1, 1, 1 } }),
        B.Ring.fromCoeffs(&primes, .{ [_]u64{0} ** 8, [_]u64{0} ** 8 }),
        B.Ring.zero(.coeff),
    }, .len = 2 };
    const b = B.Ciphertext{ .components = .{
        B.Ring.fromCoeffs(&primes, .{ [_]u64{ 16, 16, 16, 16, 16, 16, 16, 16 }, [_]u64{ 96, 96, 96, 96, 96, 96, 96, 96 } }),
        B.Ring.fromCoeffs(&primes, .{ [_]u64{0} ** 8, [_]u64{0} ** 8 }),
        B.Ring.zero(.coeff),
    }, .len = 2 };
    const c = inst.add(&a, &b);
    try testing.expectEqual(@as(usize, 2), c.numComponents());
    try testing.expectEqual(@as(u64, 0), c.components[0].limbs[0][0]); // (1+16) mod 17
    try testing.expectEqual(@as(u64, 0), c.components[0].limbs[1][0]); // (1+96) mod 97
    // sub is the inverse
    const back = inst.sub(&c, &b);
    try testing.expect(back.components[0].eql(&a.components[0]));
}

test "gate state after Part 3: both scheme cores ON" {
    // Part 2 turned on keyGen/encrypt/decrypt; Part 3 turned on the Fable
    // mul/relinearize/noiseBudget noise-management core.
    try testing.expect(gate.scheme_core_implemented);
    try testing.expect(gate.fable_core_implemented);
}
