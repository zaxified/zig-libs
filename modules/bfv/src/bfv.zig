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
//!     probabilistic pass.
//!
//! ## Arithmetic (what the multiply actually runs on)
//! The tensor is computed in an **auxiliary RNS basis of NTT-friendly primes**
//! (`mulRnsNtt`): forward-NTT the four input polynomials per auxiliary prime,
//! form the three components pointwise, inverse-NTT, then lift back with a
//! centered CRT whose basis is sized (`num_aux`) so the lift is EXACT, not
//! approximate. That replaces the `O(N²)` exact-integer schoolbook with
//! `O(num_aux·N log N)`. The schoolbook survives as `mulExactRef`: it is the
//! differential oracle (`mulRnsNtt` must be bit-identical to it), and below
//! `ntt_tensor_min_degree` it is also what `mul` dispatches to, because at
//! small `N` it is measurably faster. Word arithmetic is division-free —
//! Shoup for the NTT twiddles, Barrett elsewhere (see `modarith`).
//!
//! Still deferred: the `⌊t/q·…⌉` rescale materialises the exact integer and
//! divides by `q`, and `q_product` is a `u128` — so security-grade parameters
//! (log q ≳ 218) remain out of reach. The BEHZ/HPS **rescale-in-RNS** (fast
//! base conversion, never materialising the integer) is the increment that
//! lifts that, and it is NOT implemented here.
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
            // The tensor's integer width is no longer pinned at `i256` — it is
            // derived from the parameters (`TensorI` below), so the old
            // "2·q_bits + n_bits + t_bits + 2 ≤ 255" guard is gone. What still
            // binds is the `u128` ciphertext modulus: `q_product`, `delta`, the
            // CRT accumulator and the decrypt rescale are all `u128`, and the
            // accumulator adds one `[0,q)` term at a time, so `2q < 2^128`.
            // THIS is what still blocks security-grade parameters (log q ≳ 218);
            // lifting it is the deferred BEHZ/HPS increment (SPEC.md), which
            // removes the materialised integer altogether.
            const q_bits = 128 - @clz(q_product);
            if (q_bits > 127)
                @compileError("bfv: ciphertext modulus too large for the u128 CRT accumulator");
        }

        // ── auxiliary RNS basis for the RNS-NTT tensor (see `mul`) ───────────
        //
        // `q_product` as an arbitrary-precision comptime integer, so the bound
        // arithmetic below cannot silently wrap a `u128`.
        const q_int: comptime_int = blk: {
            var m: comptime_int = 1;
            for (primes) |p| m *= p;
            break :blk m;
        };
        /// Worst-case magnitude of ANY tensor component coefficient. Centered
        /// inputs satisfy `|x| ≤ (q−1)/2`; a negacyclic convolution coefficient
        /// sums `N` such products, and the middle component `t1` is a sum of
        /// TWO convolutions — hence the factor 2.
        const tensor_bound: comptime_int = blk: {
            const half: comptime_int = (q_int + 1) / 2;
            const n_int: comptime_int = N;
            break :blk 2 * n_int * half * half;
        };
        /// Every auxiliary prime is found by scanning DOWN from `2^62`, so each
        /// contributes at least this many bits to the product.
        const aux_min_bits: comptime_int = 61;
        /// How many auxiliary primes make `∏p_j > 2·tensor_bound`, which is
        /// exactly the condition for the centered CRT lift of the tensor to be
        /// unambiguous (and therefore for the fast path to be EXACT, not
        /// approximate).
        pub const num_aux: usize = blk: {
            var need: comptime_int = 2 * tensor_bound + 1;
            var b: comptime_int = 0;
            while (need > 0) : (b += 1) need >>= 1;
            break :blk @intCast((b + aux_min_bits - 1) / aux_min_bits);
        };
        /// Accumulator type for the auxiliary-basis CRT. Each aux prime is
        /// `< 2^62`, so `∏p_j < 2^(62·num_aux)`; the accumulator is kept below
        /// `∏p_j` by a conditional subtract after every term, so the widest
        /// value it ever holds is `< 2^(62·num_aux + 1) ≤ 2^(64·num_aux)`.
        /// Sizing it at exactly `64·num_aux` (rather than one limb wider) keeps
        /// the common `num_aux = 2` case in a NATIVE `u128`.
        const AuxU = std.meta.Int(.unsigned, 64 * num_aux);

        /// Exact width the `⌊t/q·T⌉` rescale numerator `|2·t·T + q|` needs,
        /// plus a sign bit. The tensor used to be hardcoded to `i256` — the
        /// widest thing the old comptime guard would admit — which made every
        /// parameter set pay 256-bit division whether it needed it or not.
        /// `test_mul` actually needs 85 bits, so it now rescales in `i128`.
        const rescale_bits: u16 = blk: {
            var v: comptime_int = 2 * @as(comptime_int, P.t) * tensor_bound + q_int;
            var b: u16 = 1; // sign bit
            while (v > 0) : (b += 1) v >>= 1;
            break :blk b;
        };
        /// Signed integer type the exact tensor and its rescale run in. Sized
        /// from the parameters instead of pinned at `i256`.
        pub const TensorI = std.meta.Int(.signed, @max(65, rescale_bits));

        /// The `L` per-prime NTT engines + the prime chain, built once.
        engines: [L]Engine,
        primes: [L]u64,
        /// Precomputed CRT constants for the MAIN basis. `reconstruct` in
        /// `rns.zig` recomputes `∏q`, each `∏_{k≠i} q_k` and a full
        /// `invMod` (a 62-squaring `powMod`) on EVERY call — and the scheme
        /// calls it once per coefficient, i.e. `N` times per decrypt and `4N`
        /// times per multiply. These hoist all of that to `init`.
        crt_mi: [L]u128, // ∏_{k≠i} q_k
        crt_inv: [L]u64, // (crt_mi[i] mod q_i)^{-1} mod q_i
        /// Shoup constant for `Δ mod q_i` (fixed multiplier of `scaledPlaintext`).
        delta_shoup: [L]ma.Shoup,

        /// Auxiliary basis: NTT engines over primes large enough that the
        /// EXACT integer tensor product is recoverable by CRT from its
        /// residues. This is what lets `mul` run the tensor in `O(N log N)`
        /// per prime instead of `O(N²)` over `i256`.
        aux_engines: [num_aux]Engine,
        aux_primes: [num_aux]u64,
        aux_mi: [num_aux]AuxU, // ∏_{k≠j} p_k
        aux_inv: [num_aux]u64, // (aux_mi[j] mod p_j)^{-1} mod p_j
        aux_modulus: AuxU, // ∏ p_j
        /// `q mod p_j` — folds the "centered" correction into the residue
        /// reduction without ever materialising a signed wide integer.
        q_mod_aux: [num_aux]u64,

        pub const SecretKey = struct {
            s: Ring,

            /// Securely wipe the secret key. `SecretKey` is a single
            /// fixed-size `Ring` (no heap), so zeroing the struct's bytes
            /// erases the ternary secret polynomial `s`. Call when the key
            /// is no longer needed; the struct is left zeroed and must not
            /// be reused. Idempotent — safe to call more than once.
            pub fn deinit(self: *SecretKey) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
            }
        };
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

        /// Build the instance: validates `P`, builds the `L` main NTT engines,
        /// hoists the main-basis CRT constants, and searches for + builds the
        /// `num_aux` auxiliary NTT engines the fast tensor needs.
        pub fn init() !Self {
            try P.validate();
            var local = primes;
            const engines = try ring.makeEngines(N, L, &local);

            // Main-basis CRT constants (hoisted out of `rns.Basis.reconstruct`).
            var crt_mi: [L]u128 = undefined;
            var crt_inv: [L]u64 = undefined;
            for (0..L) |i| {
                const mi = q_product / primes[i];
                crt_mi[i] = mi;
                crt_inv[i] = try ma.invMod(@intCast(mi % primes[i]), primes[i]);
            }
            var delta_shoup: [L]ma.Shoup = undefined;
            for (0..L) |i| delta_shoup[i] = ma.Shoup.init(@intCast(delta % primes[i]), primes[i]);

            // Auxiliary basis: the largest NTT-friendly primes below 2^62,
            // scanning down. Distinct by construction (strictly decreasing).
            var aux_primes: [num_aux]u64 = undefined;
            {
                const two_n: u64 = 2 * @as(u64, N);
                var cand: u64 = (@as(u64, 1) << ma.max_prime_bits) - 1;
                cand -= (cand - 1) % two_n; // largest v < 2^62 with v ≡ 1 mod 2N
                var found: usize = 0;
                while (found < num_aux) : (cand -= two_n) {
                    if (cand <= (@as(u64, 1) << @intCast(aux_min_bits))) return error.NoAuxiliaryPrimes;
                    if (!ma.isPrime(cand)) continue;
                    aux_primes[found] = cand;
                    found += 1;
                }
            }
            var aux_engines: [num_aux]Engine = undefined;
            for (0..num_aux) |j| aux_engines[j] = try Engine.init(aux_primes[j]);

            var aux_modulus: AuxU = 1;
            for (aux_primes) |p| aux_modulus *= p;
            var aux_mi: [num_aux]AuxU = undefined;
            var aux_inv: [num_aux]u64 = undefined;
            var q_mod_aux: [num_aux]u64 = undefined;
            for (0..num_aux) |j| {
                const p = aux_primes[j];
                const mi = aux_modulus / p;
                aux_mi[j] = mi;
                aux_inv[j] = try ma.invMod(@intCast(mi % p), p);
                q_mod_aux[j] = @intCast(q_product % p);
            }

            return .{
                .engines = engines,
                .primes = primes,
                .crt_mi = crt_mi,
                .crt_inv = crt_inv,
                .delta_shoup = delta_shoup,
                .aux_engines = aux_engines,
                .aux_primes = aux_primes,
                .aux_mi = aux_mi,
                .aux_inv = aux_inv,
                .aux_modulus = aux_modulus,
                .q_mod_aux = q_mod_aux,
            };
        }

        /// Exact CRT reconstruction of one coefficient's residues into
        /// `[0, q)`, using the constants hoisted at `init`. Bit-identical to
        /// `rns.Basis.reconstruct` (which stays as the differential oracle),
        /// but with no `invMod` / no `∏q` recomputation per call.
        ///
        /// The accumulator adds one `[0,q)` term at a time with a conditional
        /// subtract, so it never exceeds `2q < 2^128` (comptime-guarded).
        pub fn reconstruct(self: *const Self, residues: *const [L]u64) u128 {
            var acc: u128 = 0;
            for (0..L) |i| {
                const c: u64 = self.engines[i].modulus.mul(residues[i], self.crt_inv[i]);
                // `crt_mi[i]·c ≤ (q/q_i)·(q_i−1) < q`, so each term needs no
                // reduction of its own and `acc + term < 2q < 2^128`.
                acc += self.crt_mi[i] * @as(u128, c);
                if (acc >= q_product) acc -= q_product;
            }
            return acc;
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
        /// integer.
        ///
        /// ## Constant-time shape (what this does and does not buy)
        /// This sampler produces the secret key `s` and the errors `e,e0,e1` —
        /// the module's most sensitive values — so it must not branch on, or
        /// index by, the trit it drew. Two things were needed:
        ///
        ///   - **The draw.** `std.Random.uintLessThan(u8, 3)` is a *rejection*
        ///     loop: its iteration count depends on the value drawn, which
        ///     correlates with the trit. It is replaced by std's own
        ///     documented constant-time variant, `uintLessThanBiased`, over a
        ///     full 64-bit word — the fixed-cost multiply-shift map
        ///     `r = ⌊x·3 / 2^64⌋` (Lemire's reduction with the rejection step
        ///     dropped). The width matters: at `u8` the bias would be `3/256`,
        ///     at `u64` it is not. This is not exactly uniform: the outcomes get
        ///     `⌈2^64/3⌉ , ⌊2^64/3⌋ , ⌊2^64/3⌋` of the `2^64` words, so each
        ///     probability is within `2/(3·2^64) < 2^-63` of `1/3`. Summed over
        ///     every coefficient this module ever samples the statistical
        ///     distance from a true uniform ternary is far below `2^-50` —
        ///     cryptographically irrelevant, and unlike the rejection loop it
        ///     is fixed-cost.
        ///   - **The store.** The `switch (r)` on the secret trit is replaced by
        ///     an arithmetic mask select (`is_neg`/`is_pos` are all-ones or
        ///     all-zero words derived from `@intFromBool`, and the two cases are
        ///     mutually exclusive so `|` merges them).
        ///
        /// **Not** claimed: this is source-level constant time only. The
        /// compiler may rematerialise a branch from a mask, `random`'s own
        /// implementation is the caller's to choose (a rejection-based or
        /// buffered PRNG can reintroduce data-dependent timing upstream of
        /// here), and nothing constrains the microarchitecture. See SPEC.md
        /// "Threats / caveats" for the parts of the module that are still not
        /// constant-time at all.
        fn sampleTernary(self: *const Self, random: std.Random) Ring {
            var out = Ring.zero(.coeff);
            for (0..N) |j| {
                // r ∈ {0,1,2} ↦ −1,0,+1 — fixed cost, no rejection loop.
                const r: u64 = random.uintLessThanBiased(u64, 3);
                const is_neg: u64 = 0 -% @as(u64, @intFromBool(r == 0));
                const is_pos: u64 = 0 -% @as(u64, @intFromBool(r == 2));
                for (0..L) |i| {
                    out.limbs[i][j] = ((self.primes[i] - 1) & is_neg) | (1 & is_pos);
                }
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
                // `Δ mod q_i` is fixed for the whole limb ⇒ Shoup; the
                // coefficient reduction is Barrett. Neither divides.
                const ds = self.delta_shoup[i];
                const m = &self.engines[i].modulus;
                for (0..N) |j| out.limbs[i][j] = ds.mul(m.reduce(pt.coeffs[j]), qi);
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
            var p0 = a.mul(&s, &self.engines); // a·s
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
            var p0u = pk.p0.mul(&u, &self.engines);
            c0.addAssign(&p0u, &self.primes); // + p0·u
            c0.addAssign(&e0, &self.primes); // + e0
            var c1 = pk.p1.mul(&u, &self.engines);
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
                var term = ct.components[1].mul(&spow, &self.engines);
                acc.addAssign(&term, &self.primes);
                var i: usize = 2;
                while (i < ct.len) : (i += 1) {
                    spow = spow.mul(&sk.s, &self.engines); // s^i
                    var t2 = ct.components[i].mul(&spow, &self.engines);
                    acc.addAssign(&t2, &self.primes);
                }
            }
            // ⌊t/q · phase⌉ mod t, coefficient-wise, via exact CRT reconstruction.
            var out = Plaintext.zero(P.t);
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = acc.limbs[i][j];
                const v = self.reconstruct(&res); // in [0, q)
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

        /// Exact CRT lift of a coeff-domain ring element: every coefficient
        /// reconstructed to its canonical `[0, q)` representative. Both the
        /// reference tensor (which centers these into `i256`) and the fast
        /// tensor (which reduces them into the auxiliary basis) start here.
        fn rawCoeffs(self: *const Self, r: *const Ring) [N]u128 {
            std.debug.assert(r.domain == .coeff);
            var out: [N]u128 = undefined;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = r.limbs[i][j];
                out[j] = self.reconstruct(&res);
            }
            return out;
        }

        /// Center `[0,q)` representatives into `(−q/2, q/2]` as `i256`, so the
        /// reference tensor products stay exact.
        fn centerRaw(raw: *const [N]u128) [N]TensorI {
            const half = q_product / 2;
            var out: [N]TensorI = undefined;
            for (0..N) |j| {
                const v = raw[j];
                out[j] = if (v > half)
                    -@as(TensorI, @intCast(q_product - v))
                else
                    @as(TensorI, @intCast(v));
            }
            return out;
        }

        /// Exact centered integer coefficients of a coeff-domain ring element.
        fn centeredCoeffs(self: *const Self, r: *const Ring) [N]TensorI {
            const raw = self.rawCoeffs(r);
            return centerRaw(&raw);
        }

        /// `acc += a·b mod (X^N+1)` over the integers (exact schoolbook
        /// negacyclic convolution; |terms| ≤ N·(q/2)², guarded comptime).
        ///
        /// **This is the oracle**, not the hot path: `mul` runs the tensor
        /// through the auxiliary RNS-NTT basis (`tensorNtt`) and
        /// `mulExactRef` — this `O(N²)` `i256` schoolbook — is what the
        /// differential test asserts it is bit-identical to.
        fn negaMulAcc(a: *const [N]TensorI, b: *const [N]TensorI, acc: *[N]TensorI) void {
            for (0..N) |i| {
                for (0..N) |j| {
                    const p = a[i] * b[j];
                    const k = i + j;
                    if (k < N) acc[k] += p else acc[k - N] -= p; // X^N = −1
                }
            }
        }

        /// Residues mod the auxiliary prime `p_j` of the CENTERED integers
        /// whose `[0,q)` representatives are `raw`. Centering is folded in
        /// arithmetically: for `v > q/2` the centered value is `v − q`, so its
        /// residue is `(v mod p) − (q mod p)`. No signed wide integer, and no
        /// `i256`-by-`u64` division, ever appears.
        fn auxResidues(self: *const Self, raw: *const [N]u128, j: usize) [N]u64 {
            const p = self.aux_primes[j];
            const m = &self.aux_engines[j].modulus;
            const qm = self.q_mod_aux[j];
            const half = q_product / 2;
            var out: [N]u64 = undefined;
            for (0..N) |i| {
                const v = raw[i];
                const r = m.reduce(v);
                out[i] = if (v > half) ma.subMod(r, qm, p) else r;
            }
            return out;
        }

        /// Centered CRT lift from the auxiliary basis back to an exact `i256`.
        /// Unambiguous because `∏p_j > 2·tensor_bound ≥ 2·|T|` by construction
        /// of `num_aux` — this is what makes the NTT tensor EXACT rather than
        /// an approximation with an error term to bound.
        fn auxCenter(self: *const Self, residues: *const [num_aux]u64) TensorI {
            var acc: AuxU = 0;
            for (0..num_aux) |j| {
                const c: u64 = self.aux_engines[j].modulus.mul(residues[j], self.aux_inv[j]);
                // `aux_mi[j]·c ≤ (∏p/p_j)·(p_j−1) < ∏p`, so one conditional
                // subtract per term keeps `acc < ∏p`.
                acc += self.aux_mi[j] * @as(AuxU, c);
                if (acc >= self.aux_modulus) acc -= self.aux_modulus;
            }
            const half = self.aux_modulus / 2; // ∏p is odd ⇒ (∏p−1)/2
            return if (acc > half)
                -@as(TensorI, @intCast(self.aux_modulus - acc))
            else
                @as(TensorI, @intCast(acc));
        }

        /// The RNS-NTT exact tensor — the replacement for the `O(N²)` `i256`
        /// schoolbook. For each auxiliary prime: forward-NTT the four input
        /// polynomials, form the three tensor components by POINTWISE products
        /// in the NTT domain, inverse-NTT them, and keep the residues. A
        /// centered CRT lift over the auxiliary basis then recovers the exact
        /// integer tensor.
        ///
        /// Cost: `7` transforms + `4N` pointwise products per auxiliary prime,
        /// i.e. `O(num_aux · N log N)` word operations, against the reference's
        /// `O(N²)` `i256` (4-limb) multiplies.
        fn tensorNtt(
            self: *const Self,
            x0: *const [N]u128,
            x1: *const [N]u128,
            y0: *const [N]u128,
            y1: *const [N]u128,
            out: *[3][N]TensorI,
        ) void {
            var res: [3][num_aux][N]u64 = undefined;
            for (0..num_aux) |j| {
                const eng = &self.aux_engines[j];
                const p = eng.q;
                const m = &eng.modulus;
                var a0 = self.auxResidues(x0, j);
                var a1 = self.auxResidues(x1, j);
                var b0 = self.auxResidues(y0, j);
                var b1 = self.auxResidues(y1, j);
                eng.forward(&a0);
                eng.forward(&a1);
                eng.forward(&b0);
                eng.forward(&b1);
                var t0: [N]u64 = undefined;
                var t1: [N]u64 = undefined;
                var t2: [N]u64 = undefined;
                for (0..N) |i| {
                    t0[i] = m.mul(a0[i], b0[i]);
                    t1[i] = ma.addMod(m.mul(a0[i], b1[i]), m.mul(a1[i], b0[i]), p);
                    t2[i] = m.mul(a1[i], b1[i]);
                }
                eng.inverse(&t0);
                eng.inverse(&t1);
                eng.inverse(&t2);
                res[0][j] = t0;
                res[1][j] = t1;
                res[2][j] = t2;
            }
            for (0..3) |c| {
                for (0..N) |i| {
                    var r: [num_aux]u64 = undefined;
                    for (0..num_aux) |j| r[j] = res[c][j][i];
                    out[c][i] = self.auxCenter(&r);
                }
            }
        }

        /// `⌊t/q · T⌉ mod q` per coefficient (round half up via floor
        /// division, exact for negative T), decomposed back into RNS limbs.
        ///
        /// MEASURED NOTE (bench.zig): the two `i256` big-integer divisions here
        /// look like the obvious next target once the tensor stops being
        /// `O(N²)`, and they are NOT. Replacing the `@mod` with a division-free
        /// 4-limb Horner reduction (`2^64 mod q_i` + Barrett, exploiting
        /// `q_i | q`) was implemented and measured: it made the rescale go from
        /// ~31 ns to ~250 ns per coefficient and `mul` at N=16 from 8.8 µs to
        /// 19.4 µs — an 8x REGRESSION. LLVM lowers these `i256` divisions well
        /// (the divisor is a loop constant), and the Horner chain is fully
        /// serialised. Reverted; do not "optimise" this again without a bench.
        fn rescaleTensor(self: *const Self, tc: *const [N]TensorI) Ring {
            var out = Ring.zero(.coeff);
            const qi: TensorI = @intCast(q_product);
            const ti: TensorI = @intCast(P.t);
            for (0..N) |j| {
                const rounded = @divFloor(2 * ti * tc[j] + qi, 2 * qi);
                const v: u128 = @intCast(@mod(rounded, qi)); // canonical [0, q)
                for (0..L) |i| out.limbs[i][j] = self.engines[i].modulus.reduce(v);
            }
            return out;
        }

        /// `scalar·r` for a `[0,q)` scalar, per-limb (legal in either domain).
        /// The per-limb scalar is fixed for the whole limb ⇒ Shoup.
        fn scalarMul(self: *const Self, r: *const Ring, scalar: u128) Ring {
            var out = r.*;
            for (0..L) |i| {
                const qi = self.primes[i];
                const s = ma.Shoup.init(self.engines[i].modulus.reduce(scalar), qi);
                for (&out.limbs[i]) |*x| x.* = s.mul(x.*, qi);
            }
            return out;
        }

        /// Generate the relinearisation key: a base-`w` gadget key-switching
        /// key for `s²`. Row `i` pseudo-encrypts `w^i·s²` under `s` with a
        /// fresh ternary error `e_i`: `(b_i, a_i) = (−(a_i·s + e_i) + w^i·s²,
        /// a_i)`. `random` supplies the uniform `a_i` and ternary `e_i`.
        pub fn genRelinKey(self: *const Self, sk: *const SecretKey, random: std.Random) RelinKey {
            const s2 = sk.s.mul(&sk.s, &self.engines);
            var rlk: RelinKey = undefined;
            var w_pow: u128 = 1; // w^i < q for all rows used (see relin_digits)
            for (0..relin_digits) |i| {
                const a_i = self.sampleUniform(random);
                const e_i = self.sampleTernary(random);
                var b_i = self.scalarMul(&s2, w_pow); // w^i·s²
                var mask = a_i.mul(&sk.s, &self.engines); // a_i·s
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
        /// Ring degree at or above which `mul` takes the RNS-NTT tensor. Below
        /// it the `O(N²)` schoolbook is genuinely faster: at small `N` the
        /// per-multiply fixed costs (CRT lift + the `⌊t/q·⌉` rescale) dominate
        /// both paths, and `7·num_aux` transforms cost more than `N²` narrow
        /// multiplies. MEASURED (bench.zig, ReleaseFast, this host — schoolbook
        /// vs RNS-NTT, so >1 means the NTT path wins):
        ///
        /// | N   | q≈2^36 (num_aux=2) | q≈2^60 (num_aux=3) |
        /// |-----|--------------------|--------------------|
        /// |  16 | 1.1x  (0.9–1.1)    | 1.1x  (1.0–1.1)    |
        /// |  32 | 1.5x               | 1.3x               |
        /// |  64 | 2.5x               | 2.0x               |
        /// | 256 | 3.5x               | 2.8x               |
        /// | 512 | 5.9x               | 4.7x               |
        ///
        /// At N=16 the two are within run-to-run noise (the parenthesised range
        /// is across repeats); `32` is the first degree where the NTT path wins
        /// consistently at BOTH modulus sizes. The shipped sets land on either
        /// side deliberately:
        /// `test_tiny`/`test_mul` (N=8/16) keep the schoolbook, `bfv_toy`
        /// (N=1024) takes the NTT tensor.
        pub const ntt_tensor_min_degree: usize = 32;

        /// Homomorphic multiply. Dispatches at COMPTIME between the two tensor
        /// implementations — both are exact and, by the differential test,
        /// bit-identical; the choice is purely which is faster at this `N`.
        pub fn mul(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            return if (comptime N >= ntt_tensor_min_degree)
                self.mulRnsNtt(x, y)
            else
                self.mulExactRef(x, y);
        }

        /// Tensor via the auxiliary RNS-NTT basis: `O(num_aux · N log N)`.
        /// Called directly by the differential test at EVERY parameter set, so
        /// it stays covered even where `mul` does not dispatch to it.
        pub fn mulRnsNtt(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == 2 and y.len == 2);
            const x0 = self.rawCoeffs(&x.components[0]);
            const x1 = self.rawCoeffs(&x.components[1]);
            const y0 = self.rawCoeffs(&y.components[0]);
            const y1 = self.rawCoeffs(&y.components[1]);
            var t: [3][N]TensorI = undefined;
            self.tensorNtt(&x0, &x1, &y0, &y1, &t);
            return .{ .components = .{
                self.rescaleTensor(&t[0]),
                self.rescaleTensor(&t[1]),
                self.rescaleTensor(&t[2]),
            }, .len = 3 };
        }

        /// The ORIGINAL `O(N²)` exact-integer schoolbook multiply, kept as the
        /// differential ORACLE for `mulRnsNtt` — and, below
        /// `ntt_tensor_min_degree`, as the path `mul` actually takes.
        pub fn mulExactRef(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == 2 and y.len == 2);
            const x0 = self.centeredCoeffs(&x.components[0]);
            const x1 = self.centeredCoeffs(&x.components[1]);
            const y0 = self.centeredCoeffs(&y.components[0]);
            const y1 = self.centeredCoeffs(&y.components[1]);
            var t0 = [_]TensorI{0} ** N;
            var t1 = [_]TensorI{0} ** N;
            var t2 = [_]TensorI{0} ** N;
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
            // Exact base-w digits of every coefficient of c2.
            var digits: [relin_digits][N]u64 = undefined;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = ct.components[2].limbs[i][j];
                var v = self.reconstruct(&res); // [0, q)
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
                    const m = &self.engines[l].modulus;
                    for (0..N) |j| d.limbs[l][j] = m.reduce(digits[i][j]);
                }
                var tb = d.mul(&rlk.b[i], &self.engines);
                c0.addAssign(&tb, &self.primes);
                var ta = d.mul(&rlk.a[i], &self.engines);
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
                var term = ct.components[1].mul(&spow, &self.engines);
                acc.addAssign(&term, &self.primes);
                var i: usize = 2;
                while (i < ct.len) : (i += 1) {
                    spow = spow.mul(&sk.s, &self.engines);
                    var t2 = ct.components[i].mul(&spow, &self.engines);
                    acc.addAssign(&t2, &self.primes);
                }
            }
            const half = q_product / 2;
            var vmax: u128 = 0;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = acc.limbs[i][j];
                const phase = self.reconstruct(&res); // [0, q)
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

test "SecretKey.deinit zeroes the secret ring" {
    const B = Bfv(params.test_tiny);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    const rnd = prng.random();
    var kp = inst.keyGen(rnd);
    // Sanity: the freshly generated ternary key is not all-zero (astronomically
    // unlikely for a real key, and this instance's seed is fixed).
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&kp.sk), 0));
    kp.sk.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&kp.sk), 0));
}
