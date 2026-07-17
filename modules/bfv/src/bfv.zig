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
//! ## Part-1 status — TYPES + CODECS + `add` are REAL; the scheme cores are
//! ## gated (see `gate.zig`, SPEC.md "Fable boundary"):
//!   - **REAL today:** the `SecretKey`/`PublicKey`/`RelinKey`/`Ciphertext`
//!     types, their byte codecs, `Ciphertext.add`/`sub` (pure ring ops, not
//!     noise-sensitive), and `numComponents`.
//!   - **Gated `scheme_core_implemented` (Part 2, Opus):** `keyGen`,
//!     `encrypt`, `decrypt` — textbook, SEAL-KAT-able.
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

        // ── Gated: scheme core (Part 2, Opus — SEAL-KAT-able) ────────────────

        /// Generate a BFV keypair. `random` supplies the secret (ternary) key,
        /// public-key mask `a`, and error `e`.
        pub fn keyGen(self: *const Self, random: std.Random) KeyPair {
            _ = self;
            _ = random;
            if (!gate.scheme_core_implemented)
                @panic("TODO(opus/scheme): BFV keyGen — ternary s, pk=(-(a·s+e), a). Part 2. See gate.zig / SPEC.md.");
            unreachable;
        }

        /// Encrypt `pt ∈ R_t`: `c0 = Δ·m + p0·u + e0`, `c1 = p1·u + e1`,
        /// `Δ = ⌊q/t⌋`. `random` supplies `u,e0,e1`.
        pub fn encrypt(self: *const Self, pk: *const PublicKey, pt: *const Plaintext, random: std.Random) Ciphertext {
            _ = .{ self, pk, pt, random };
            if (!gate.scheme_core_implemented)
                @panic("TODO(opus/scheme): BFV encrypt — Δ·m + pk·u + e, RNS. Part 2. See gate.zig / SPEC.md.");
            unreachable;
        }

        /// Decrypt: `⌊t/q·(c0 + c1·s + …)⌉ mod t`. The rounding IS noise
        /// management — but it has a byte-exact SEAL anchor, so Part 2/Opus.
        pub fn decrypt(self: *const Self, sk: *const SecretKey, ct: *const Ciphertext) Plaintext {
            _ = .{ self, sk, ct };
            if (!gate.scheme_core_implemented)
                @panic("TODO(opus/scheme): BFV decrypt — ⌊t/q·(c0+c1·s)⌉ mod t, RNS scale-and-round. Part 2. See gate.zig / SPEC.md.");
            unreachable;
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

test "gated scheme cores are unreachable while flags are false (compile-only shape)" {
    // We do NOT call the gated cores here (they @panic by design). This test
    // documents the gate wiring and that the flags are OFF in Part 1.
    try testing.expect(!gate.scheme_core_implemented);
    try testing.expect(!gate.fable_core_implemented);
}
