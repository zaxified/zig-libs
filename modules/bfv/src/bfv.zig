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
//! ## Status — Part 1 (backbone + types) + Part 2 (scheme core) are REAL:
//!   - **REAL (Part 1):** the `SecretKey`/`PublicKey`/`RelinKey`/`Ciphertext`
//!     types, their byte codecs, `Ciphertext.add`/`sub` (pure ring ops, not
//!     noise-sensitive), and `numComponents`.
//!   - **REAL (Part 2, Opus — `scheme_core_implemented`):** `keyGen`,
//!     `encrypt`, `decrypt` — textbook RLWE; the `Δ`-scale decrypt is anchored
//!     by a deterministic noiseless-ciphertext KAT + the enc/dec round-trip and
//!     homomorphic-add end-to-end tests.
//!   - **Gated `fable_core_implemented` (Part 3, Fable):** `mul`,
//!     `relinearize`, `noiseBudget` — the noise-management core.
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

        /// The `L` per-prime NTT engines + the prime chain, built once.
        engines: [L]Engine,
        primes: [L]u64,

        pub const SecretKey = struct { s: Ring };
        pub const PublicKey = struct { p0: Ring, p1: Ring };
        pub const KeyPair = struct { sk: SecretKey, pk: PublicKey };

        /// Relinearisation / evaluation key: a key-switching key for `s^2`.
        /// Layout (decomposition-base gadget) is finalised with the Part-3
        /// Fable core; Part 1 fixes only the outer shape.
        pub const RelinKey = struct {
            /// gadget rows; `[]` until Part 3 wires the base-decomposition.
            b: []Ring = &.{},
            a: []Ring = &.{},
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

        // ── Gated: Fable core (Part 3 — noise management) ────────────────────

        /// Generate a relinearisation key for `s^2` (key-switching key). Part 3.
        pub fn genRelinKey(self: *const Self, sk: *const SecretKey, random: std.Random) RelinKey {
            _ = .{ self, sk, random };
            if (!gate.fable_core_implemented)
                @panic("TODO(fable/core): relin-key gen — gadget-decomposed key-switching key for s². Part 3. See gate.zig / SPEC.md.");
            unreachable;
        }

        /// Homomorphic multiply → a 3-component ciphertext. The genuine Fable
        /// core: tensor `(c0,c1)⊗(d0,d1)` over `R`, then the `⌊t/q·…⌉` RNS
        /// rescale (where noise is silently mismanageable). Part 3.
        pub fn mul(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            _ = .{ self, x, y };
            if (!gate.fable_core_implemented)
                @panic("TODO(fable/core): BFV mul — tensor + ⌊t/q·…⌉ rescale (noise budget). Part 3. See gate.zig / SPEC.md.");
            unreachable;
        }

        /// Relinearise a 3-component ciphertext back to 2 components via the
        /// relin key (key-switch on the `c2·s²` term). The genuine Fable core:
        /// a wrong key-switch decrypts subtly wrong. Part 3.
        pub fn relinearize(self: *const Self, ct: *const Ciphertext, rlk: *const RelinKey) Ciphertext {
            _ = .{ self, ct, rlk };
            if (!gate.fable_core_implemented)
                @panic("TODO(fable/core): BFV relinearize — key-switch c2·s² down. Part 3. See gate.zig / SPEC.md.");
            unreachable;
        }

        /// Remaining noise budget (bits) of `ct` under `sk`; `0` == exhausted
        /// (decryption failure). The invariant the Fable multiply must keep
        /// honest. Part 3.
        pub fn noiseBudget(self: *const Self, sk: *const SecretKey, ct: *const Ciphertext) u32 {
            _ = .{ self, sk, ct };
            if (!gate.fable_core_implemented)
                @panic("TODO(fable/core): noiseBudget — log2(q / (2·|noise|)). Part 3. See gate.zig / SPEC.md.");
            unreachable;
        }
    };
}

// ── tests: the REAL, ungated scheme surface (types + codecs + add) ────────────

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

test "gate state after Part 2: scheme core ON, Fable core still OFF" {
    // Part 2 turns on keyGen/encrypt/decrypt; the Fable mul/relin/noiseBudget
    // core stays gated for Part 3 (its cores @panic until then).
    try testing.expect(gate.scheme_core_implemented);
    try testing.expect(!gate.fable_core_implemented);
}
