// SPDX-License-Identifier: MIT

//! tfhe — TFHE/FHEW-style programmable **gate bootstrapping**: the scheme layer
//! over the mechanical ring/gadget/torus backbone. `Tfhe(P)` is an instance for
//! a compile-time parameter set `P` (`k = 1`, the standard RLWE choice).
//!
//! Model after Chillotti–Gama–Georgieva–Izabachène (TFHE, J. Cryptology 2020;
//! ePrint 2016/870) and Ducas–Micciancio (FHEW, EUROCRYPT 2015). Bootstrapping
//! turns leveled FHE into *unbounded-depth* FHE: after every gate we blind-
//! rotate a LUT to homomorphically re-decode the message and emit a FRESH
//! low-noise ciphertext, so noise never accumulates across depth.
//!
//! ## What is REAL here (mechanical, ungated)
//!   - LWE (dimension-generic) + GLWE (`k=1`) + GGSW keygen / encrypt / decrypt.
//!   - Bootstrap-key generation (GGSW encryptions of the LWE secret bits) and
//!     key-switch-key generation.
//!   - Modulus switch (`q → 2N`), sample extraction (GLWE coeff → LWE), and
//!     LWE→LWE key switching.
//!   - GLWE monomial rotation, add/sub, trivial encryption, and the signed
//!     GLWE gadget decomposition the external product consumes.
//!   - `clearBootstrap` — the NOISELESS cleartext LUT+rotation reference the
//!     homomorphic `bootstrap` must reproduce (the anti-self-consistency oracle).
//!
//! ## What is GATED (the Fable core — `gate.fable_core_implemented`)
//!   - `externalProduct` (GGSW ⊠ GLWE), `cmux`, `blindRotate`, `bootstrap`.
//!
//! Randomness is caller-supplied (`std.Random`) so the module is `platform =
//! .any` and tests are reproducible.

const std = @import("std");
const params = @import("params.zig");
const torus = @import("torus.zig");
const polymod = @import("poly.zig");
const gadget = @import("gadget.zig");
const gate = @import("gate.zig");

const T = torus.Torus;

/// `Tfhe(P)` — a TFHE instance for the compile-time parameter set `P`.
pub fn Tfhe(comptime P: params.Params) type {
    const n = P.n;
    const N = P.N;
    const ell = P.ell;
    const ell_ks = P.ell_ks;
    const bg_bits = P.bg_bits;
    const bks_bits = P.bks_bits;
    const B: u32 = P.err_bound;
    const two_n = 2 * N;

    return struct {
        const Self = @This();
        pub const parameters = P;
        pub const ring_degree = N;
        pub const lwe_dim = n;
        /// Message scale for a bit: `Δ = q/4` (padding-bit convention).
        pub const delta: T = 1 << 30;
        pub const delta_log: u6 = 30;
        pub const log_two_n: u6 = P.logTwoN();
        pub const Poly = polymod.Poly(N);

        // ── ciphertext / key types ───────────────────────────────────────────

        /// LWE ciphertext of dimension `dim`: `(a ∈ Z_q^dim, b ∈ Z_q)`,
        /// `b = ⟨a,s⟩ + μ + e`.
        pub fn Lwe(comptime dim: usize) type {
            return struct { a: [dim]T, b: T };
        }
        /// Binary LWE secret key of dimension `dim`.
        pub fn LweKey(comptime dim: usize) type {
            return struct { s: [dim]T };
        }
        /// Input/output LWE (under the small key `s ∈ {0,1}^n`).
        pub const LweN = Lwe(n);
        /// LWE extracted from a GLWE (under the "big" key `s_ext ∈ {0,1}^{kN}`).
        pub const LweBig = Lwe(N);

        /// GLWE (`k=1`) secret key: one binary polynomial.
        pub const GlweKey = struct { s: Poly };
        /// GLWE (`k=1`) ciphertext `(a, b)`, `b = a·s + μ + e`.
        pub const Glwe = struct { a: Poly, b: Poly };

        /// GGSW ciphertext of a message `μ`: `(k+1)·ℓ = 2ℓ` GLWE rows. Rows
        /// `[0,ℓ)` carry the gadget term `μ·q/B_g^{i+1}` in the MASK component
        /// `a`; rows `[ℓ,2ℓ)` carry it in the BODY component `b`. The external
        /// product pairs these with the two gadget-decomposed halves of the
        /// input GLWE (see `decomposeGlwe`).
        pub const Ggsw = struct { rows: [2 * ell]Glwe };

        /// Bootstrap key: a GGSW encryption of each LWE secret bit `s_i` under
        /// the GLWE key.
        pub const BootstrapKey = struct { ggsw: [n]Ggsw };

        /// Key-switch key: for each big-key coordinate `j` and gadget level `i`,
        /// an `LweN` encryption of `s_ext[j]·q/B_ks^{i+1}` under the small key.
        pub const KeySwitchKey = struct { rows: [N][ell_ks]LweN };

        pub fn init() !Self {
            try P.validate();
            return .{};
        }

        // ── samplers (caller-supplied RNG) ───────────────────────────────────

        fn sampleBit(random: std.Random) T {
            return random.uintLessThan(u32, 2);
        }
        /// Error uniform in `[−B, B]`, as a torus element (two's complement).
        fn sampleError(random: std.Random) T {
            const bi: i32 = @intCast(B);
            const e = random.intRangeAtMost(i32, -bi, bi);
            return @bitCast(e);
        }
        fn sampleUniformPoly(random: std.Random) Poly {
            var out: Poly = undefined;
            for (&out.c) |*x| x.* = random.int(T);
            return out;
        }
        fn sampleErrorPoly(random: std.Random) Poly {
            var out: Poly = undefined;
            for (&out.c) |*x| x.* = sampleError(random);
            return out;
        }

        // ── keygen ───────────────────────────────────────────────────────────

        pub fn lweKeyGen(comptime dim: usize, random: std.Random) LweKey(dim) {
            var key: LweKey(dim) = undefined;
            for (&key.s) |*x| x.* = sampleBit(random);
            return key;
        }

        pub fn glweKeyGen(random: std.Random) GlweKey {
            var s = Poly.zero();
            for (&s.c) |*x| x.* = sampleBit(random);
            return .{ .s = s };
        }

        /// The LWE key `s_ext ∈ {0,1}^N` obtained by reading the GLWE key's
        /// polynomial coefficients — the key under which `sampleExtract`'s
        /// output decrypts.
        pub fn extractGlweKey(gk: *const GlweKey) LweKey(N) {
            var key: LweKey(N) = undefined;
            @memcpy(&key.s, &gk.s.c);
            return key;
        }

        // ── LWE encrypt / decrypt ────────────────────────────────────────────

        pub fn lweEncrypt(comptime dim: usize, key: *const LweKey(dim), mu: T, random: std.Random) Lwe(dim) {
            var ct: Lwe(dim) = undefined;
            var b: T = mu +% sampleError(random);
            for (&ct.a, key.s) |*ai, si| {
                ai.* = random.int(T);
                b +%= ai.* *% si;
            }
            ct.b = b;
            return ct;
        }

        /// Phase `b − ⟨a,s⟩ = μ + e`.
        pub fn lwePhase(comptime dim: usize, key: *const LweKey(dim), ct: *const Lwe(dim)) T {
            var acc: T = ct.b;
            for (ct.a, key.s) |ai, si| acc -%= ai *% si;
            return acc;
        }

        /// Decrypt a bit LWE (`Δ = q/4`).
        pub fn lweDecryptBit(comptime dim: usize, key: *const LweKey(dim), ct: *const Lwe(dim)) u32 {
            return torus.decode(lwePhase(dim, key, ct), delta_log, 2);
        }

        // ── GLWE encrypt / decrypt ───────────────────────────────────────────

        /// Encrypt an already-scaled plaintext polynomial `μ`: `b = a·s + μ + e`.
        pub fn glweEncrypt(key: *const GlweKey, msg: *const Poly, random: std.Random) Glwe {
            const a = sampleUniformPoly(random);
            var b = a.mul(&key.s);
            b.addAssign(msg);
            const e = sampleErrorPoly(random);
            b.addAssign(&e);
            return .{ .a = a, .b = b };
        }

        pub fn glweEncryptZero(key: *const GlweKey, random: std.Random) Glwe {
            const z = Poly.zero();
            return glweEncrypt(key, &z, random);
        }

        /// Phase `b − a·s = μ + e`.
        pub fn glwePhase(key: *const GlweKey, ct: *const Glwe) Poly {
            const as = ct.a.mul(&key.s);
            return ct.b.sub(&as);
        }

        /// Trivial (noiseless, key-independent) GLWE of `μ`: `(0, μ)`. Used to
        /// initialise the blind-rotation accumulator.
        pub fn glweTrivial(msg: *const Poly) Glwe {
            return .{ .a = Poly.zero(), .b = msg.* };
        }

        pub fn glweAdd(x: *const Glwe, y: *const Glwe) Glwe {
            return .{ .a = x.a.add(&y.a), .b = x.b.add(&y.b) };
        }
        pub fn glweSub(x: *const Glwe, y: *const Glwe) Glwe {
            return .{ .a = x.a.sub(&y.a), .b = x.b.sub(&y.b) };
        }
        /// Multiply a GLWE by the monomial `X^e` (rotate both components).
        pub fn glweMulMonomial(x: *const Glwe, e: usize) Glwe {
            return .{ .a = x.a.mulMonomial(e), .b = x.b.mulMonomial(e) };
        }

        // ── GGSW / bootstrap key / key-switch key ────────────────────────────

        /// Encrypt a message polynomial `μ` as a GGSW (gadget matrix). Each row
        /// is a fresh GLWE(0) plus the gadget term `μ·q/B_g^{i+1}` in the
        /// component the block selects.
        pub fn ggswEncryptPoly(key: *const GlweKey, msg: *const Poly, random: std.Random) Ggsw {
            var g: Ggsw = undefined;
            for (0..ell) |i| {
                const w = torus.gadgetWeight(bg_bits, i);
                const scaled = msg.scalarMul(w);
                // block A: gadget term in mask component `a`.
                var ra = glweEncryptZero(key, random);
                ra.a.addAssign(&scaled);
                g.rows[i] = ra;
                // block B: gadget term in body component `b`.
                var rb = glweEncryptZero(key, random);
                rb.b.addAssign(&scaled);
                g.rows[ell + i] = rb;
            }
            return g;
        }

        /// GGSW of a scalar (constant polynomial), e.g. a secret key bit.
        pub fn ggswEncryptScalar(key: *const GlweKey, m: T, random: std.Random) Ggsw {
            const c = Poly.constant(m);
            return ggswEncryptPoly(key, &c, random);
        }

        /// Bootstrap key: `GGSW(s_i)` for each LWE secret bit, under the GLWE key.
        pub fn bootstrapKeyGen(lwe_key: *const LweKey(n), glwe_key: *const GlweKey, random: std.Random) BootstrapKey {
            var bsk: BootstrapKey = undefined;
            for (0..n) |i| bsk.ggsw[i] = ggswEncryptScalar(glwe_key, lwe_key.s[i], random);
            return bsk;
        }

        /// Key-switch key from the big (extracted) GLWE key to the small LWE key.
        pub fn keySwitchKeyGen(glwe_key: *const GlweKey, small_key: *const LweKey(n), random: std.Random) KeySwitchKey {
            const big = extractGlweKey(glwe_key);
            var ksk: KeySwitchKey = undefined;
            for (0..N) |j| {
                for (0..ell_ks) |i| {
                    const msg = big.s[j] *% torus.gadgetWeight(bks_bits, i);
                    ksk.rows[j][i] = lweEncrypt(n, small_key, msg, random);
                }
            }
            return ksk;
        }

        // ── sample extraction / key switching (mechanical) ───────────────────

        /// Extract an `LweBig` encrypting coefficient 0 of the GLWE plaintext,
        /// under `extractGlweKey`. The mask uses the negacyclic sign flip
        /// `a_ext[j] = −a(X)_{N−j}` (`j ≥ 1`), `a_ext[0] = a(X)_0`, so that
        /// `⟨a_ext, s_ext⟩ = (a·s)_0`.
        pub fn sampleExtract(ct: *const Glwe) LweBig {
            var out: LweBig = undefined;
            out.b = ct.b.c[0];
            out.a[0] = ct.a.c[0];
            var j: usize = 1;
            while (j < N) : (j += 1) out.a[j] = 0 -% ct.a.c[N - j];
            return out;
        }

        /// Key-switch an `LweBig` (under `s_ext`) down to an `LweN` (under the
        /// small key): `out = (0, b) − Σ_j Σ_i decompose(a_ext[j])_i · KSK[j][i]`.
        pub fn keySwitch(ksk: *const KeySwitchKey, ct: *const LweBig) LweN {
            var out: LweN = .{ .a = [_]T{0} ** n, .b = ct.b };
            for (0..N) |j| {
                const digits = gadget.decompose(bks_bits, ell_ks, ct.a[j]);
                for (0..ell_ks) |i| {
                    const du: T = @bitCast(digits[i]);
                    const row = &ksk.rows[j][i];
                    out.b -%= du *% row.b;
                    for (&out.a, row.a) |*om, rm| om.* -%= du *% rm;
                }
            }
            return out;
        }

        // ── message / LUT helpers (mechanical) ───────────────────────────────

        pub fn encodeBit(b: u32) T {
            return torus.encode(b, delta);
        }
        pub fn decodeBit(mu: T) u32 {
            return torus.decode(mu, delta_log, 2);
        }
        pub fn modSwitchScalar(x: T) usize {
            return torus.modSwitch(x, log_two_n);
        }

        /// Build the negacyclic LUT (test polynomial) for a function over a
        /// message space of `p = 2^p_log` slots on the torus, of which the lower
        /// half `p/2` are valid data messages. `outs[m]` is the (already
        /// Δ-scaled) desired output for data message `m ∈ [0, p/2)`. The upper
        /// half is filled by the negacyclic anti-symmetry `o(r+N) = −o(r)`, so
        /// blind-rotating by `−phase` and reading coefficient 0 yields
        /// `outs[decode(phase)]`.
        pub fn testPolynomial(comptime p_log: u6, outs: [1 << (p_log - 1)]T) Poly {
            const p = 1 << p_log;
            const half = p / 2;
            var lut = Poly.zero();
            for (0..N) |j| {
                // nearest of `p` message slots to torus position `j` (of 2N).
                const idx = ((j * p + N) / two_n) % p;
                lut.c[j] = if (idx < half) outs[idx] else 0 -% outs[idx - half];
            }
            return lut;
        }

        /// NOISELESS cleartext reference: the torus value blind rotation must
        /// place in coefficient 0 of the accumulator, given the input LWE and
        /// its secret key. `exp = (Σ ã_i·s_i) − b̃ (mod 2N)`; result =
        /// `(X^exp · lut)_0`. This is the anti-self-consistency oracle for the
        /// gated `bootstrap` — it exercises the SAME modulus-switch + rotation
        /// indexing the homomorphic path does, with no encryption.
        pub fn clearBootstrap(lut: *const Poly, ct: *const LweN, key: *const LweKey(n)) T {
            var rot: usize = (two_n - (modSwitchScalar(ct.b) % two_n)) % two_n; // X^{−b̃}
            for (ct.a, key.s) |ai, si| {
                if (si == 1) rot = (rot + modSwitchScalar(ai)) % two_n;
            }
            return lut.mulMonomial(rot).constTerm();
        }

        /// Signed GLWE gadget decomposition consumed by the external product:
        /// `out[0..ℓ)` are the `ℓ` digit-polynomials of the mask `a`, `out[ℓ..2ℓ)`
        /// those of the body `b` (digit `i` of coefficient `j`, as a torus
        /// element). Mechanical/exact — pairs row-for-row with `Ggsw.rows`.
        pub fn decomposeGlwe(ct: *const Glwe) [2 * ell]Poly {
            var out: [2 * ell]Poly = undefined;
            for (0..ell) |i| {
                out[i] = Poly.zero();
                out[ell + i] = Poly.zero();
            }
            for (0..N) |j| {
                const da = gadget.decompose(bg_bits, ell, ct.a.c[j]);
                const db = gadget.decompose(bg_bits, ell, ct.b.c[j]);
                for (0..ell) |i| {
                    out[i].c[j] = @bitCast(da[i]);
                    out[ell + i].c[j] = @bitCast(db[i]);
                }
            }
            return out;
        }

        // ── the Fable core (GATED — gate.fable_core_implemented) ─────────────
        //
        // Cut-line: everything above is mechanical (deterministic or bounded-
        // noise, independently testable). The four functions below carry the
        // TFHE soundness — the CMux selector, the accumulator's rotation
        // exponents, and the noise growth of the external product — and have NO
        // external byte-exact KAT. They are the genuine Fable core.

        /// GGSW ⊠ GLWE → GLWE. Decompose `ct` (`decomposeGlwe`), then
        /// `out = Σ_{r=0}^{2ℓ−1} decomp[r] · ggsw.rows[r]` (scalar-poly × GLWE,
        /// accumulated component-wise). Result encrypts `μ_ggsw · plaintext(ct)`
        /// with controlled noise.
        ///
        /// Why the plain positive accumulation is correct under THIS module's
        /// conventions (`b = a·s + μ + e`; block A rows carry `+μ·w_i` in the
        /// MASK, block B rows `+μ·w_i` in the BODY; `decomposeGlwe` returns mask
        /// digits in `[0,ℓ)`, body digits in `[ℓ,2ℓ)`):
        ///
        ///   phase(out) = Σ_r d_r·phase(rows[r])
        ///              = Σ_i d^a_i·(e_i − μ·w_i·s) + Σ_i d^b_i·(μ·w_i + e'_i)
        ///              ≈ μ·(b − a·s) + Σ_r d_r·e_r  =  μ·phase(ct) + noise
        ///
        /// (block A's phase is `e − μ·w·s` because the gadget term sits in the
        /// mask, so the `−μ·s·a` piece emerges from the rows themselves — no
        /// extra negation anywhere). The signed digits are two's-complement
        /// `u32` polynomials, and the wrapping schoolbook `mul` is exact mod
        /// `2^32`, so signed×torus products need no special handling.
        pub fn externalProduct(ggsw: *const Ggsw, ct: *const Glwe) Glwe {
            const d = decomposeGlwe(ct);
            var out: Glwe = .{ .a = Poly.zero(), .b = Poly.zero() };
            for (0..2 * ell) |r| {
                const pa = d[r].mul(&ggsw.rows[r].a);
                const pb = d[r].mul(&ggsw.rows[r].b);
                out.a.addAssign(&pa);
                out.b.addAssign(&pb);
            }
            return out;
        }

        /// CMux: `out = d0 + C ⊠ (d1 − d0)` — selects `d1` if `C` encrypts 1,
        /// else `d0`, homomorphically. With `C = GGSW(c)`, `c ∈ {0,1}`:
        /// phase(out) ≈ phase(d0) + c·(phase(d1) − phase(d0)).
        pub fn cmux(ctrl: *const Ggsw, d0: *const Glwe, d1: *const Glwe) Glwe {
            const diff = glweSub(d1, d0);
            const sel = externalProduct(ctrl, &diff);
            return glweAdd(d0, &sel);
        }

        /// Blind rotation: `acc ← trivial(X^{−b̃}·lut)`; for each `i`,
        /// `acc ← CMux(bsk.ggsw[i], acc, X^{ã_i}·acc)`. Returns a GLWE encrypting
        /// `X^{−(b̃ − Σ ã_i s_i)}·lut`. `a_tilde` and `b_tilde` are mod-switched
        /// into `[0, 2N)`.
        ///
        /// Exponent algebra (matches `clearBootstrap` exactly): the initial
        /// rotation is `X^{−b̃} = X^{2N − b̃}` (negacyclic period `2N`); each
        /// CMux step multiplies by `X^{+ã_i}` iff `s_i = 1`, so the final
        /// accumulated exponent is `−b̃ + Σ ã_i·s_i (mod 2N)`. The CMux runs
        /// unconditionally for every `i` — when `ã_i = 0` the two branches are
        /// identical (`d1 − d0 = 0` decomposes to all-zero digits, so the
        /// external product is exactly zero and no branch on data is needed).
        pub fn blindRotate(bsk: *const BootstrapKey, lut: *const Poly, b_tilde: usize, a_tilde: *const [n]usize) Glwe {
            const neg_b = (two_n - (b_tilde % two_n)) % two_n; // X^{−b̃}
            const rotated_lut = lut.mulMonomial(neg_b);
            var acc = glweTrivial(&rotated_lut);
            for (0..n) |i| {
                const rot = glweMulMonomial(&acc, a_tilde[i] % two_n); // X^{+ã_i}·acc
                acc = cmux(&bsk.ggsw[i], &acc, &rot);
            }
            return acc;
        }

        /// Programmable gate bootstrap: modulus-switch `ct` into `[0,2N)`,
        /// blind-rotate `lut`, sample-extract coefficient 0, and key-switch back
        /// to the small key — yielding a FRESH `LweN` encrypting the LUT of the
        /// input bit with reset noise. The blind rotation places
        /// `(X^{−phasẽ}·lut)_0 = lut(phase(ct))` in coefficient 0, where
        /// `phasẽ = b̃ − Σ ã_i·s_i` is the mod-switched phase.
        pub fn bootstrap(bsk: *const BootstrapKey, ksk: *const KeySwitchKey, lut: *const Poly, ct: *const LweN) LweN {
            var a_tilde: [n]usize = undefined;
            for (&a_tilde, ct.a) |*at, ai| at.* = modSwitchScalar(ai);
            const b_tilde = modSwitchScalar(ct.b);
            const acc = blindRotate(bsk, lut, b_tilde, &a_tilde);
            const big = sampleExtract(&acc);
            return keySwitch(ksk, &big);
        }
    };
}

// ── tests: the REAL, ungated scheme surface ──────────────────────────────────

const testing = std.testing;
const Toy = Tfhe(params.toy);

test "instance builds and exposes the toy shape" {
    _ = try Toy.init();
    try testing.expectEqual(@as(usize, 256), Toy.ring_degree);
    try testing.expectEqual(@as(usize, 64), Toy.lwe_dim);
    try testing.expectEqual(@as(u6, 9), Toy.log_two_n);
}

test "LWE encrypt/decrypt round-trips a bit (bounded noise ≪ Δ/2)" {
    const inst = try Toy.init();
    _ = inst;
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    const key = Toy.lweKeyGen(64, rnd);
    for (0..50) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncrypt(64, &key, Toy.encodeBit(b), rnd);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &key, &ct));
    }
}

test "GLWE encrypt/decrypt round-trips a scaled plaintext" {
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    const key = Toy.glweKeyGen(rnd);
    // plaintext: Δ·(coefficient bits)
    var msg = Toy.Poly.zero();
    for (&msg.c, 0..) |*c, i| c.* = Toy.encodeBit(@intCast(i & 1));
    const ct = Toy.glweEncrypt(&key, &msg, rnd);
    const phase = Toy.glwePhase(&key, &ct);
    for (phase.c, msg.c) |ph, m| {
        // |phase − msg| ≤ err_bound
        const err = @min(ph -% m, m -% ph);
        try testing.expect(err <= params.toy.err_bound);
    }
}

test "sampleExtract yields an LWE of coefficient 0 (decrypts under extracted key)" {
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    const gk = Toy.glweKeyGen(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    for (0..20) |_| {
        const b0 = rnd.uintLessThan(u32, 2);
        var msg = Toy.Poly.zero();
        msg.c[0] = Toy.encodeBit(b0);
        // fill other coeffs with arbitrary scaled bits (must NOT leak into coeff 0)
        for (msg.c[1..]) |*c| c.* = Toy.encodeBit(rnd.uintLessThan(u32, 2));
        const ct = Toy.glweEncrypt(&gk, &msg, rnd);
        const lwe = Toy.sampleExtract(&ct);
        try testing.expectEqual(b0, Toy.lweDecryptBit(N_big, &big_key, &lwe));
    }
}
const N_big = params.toy.N;

test "keySwitch preserves the message (big key → small key)" {
    var prng = std.Random.DefaultPrng.init(4);
    const rnd = prng.random();
    const gk = Toy.glweKeyGen(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    const small_key = Toy.lweKeyGen(64, rnd);
    const ksk = Toy.keySwitchKeyGen(&gk, &small_key, rnd);
    for (0..20) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct_big = Toy.lweEncrypt(N_big, &big_key, Toy.encodeBit(b), rnd);
        const ct_small = Toy.keySwitch(&ksk, &ct_big);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &small_key, &ct_small));
    }
}

test "decomposeGlwe recomposes each component within the gadget error bound" {
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    const gk = Toy.glweKeyGen(rnd);
    const ct = Toy.glweEncryptZero(&gk, rnd);
    const d = Toy.decomposeGlwe(&ct);
    const bound = gadget.maxError(params.toy.bg_bits, params.toy.ell);
    for (0..N_big) |j| {
        var acc_a: T = 0;
        var acc_b: T = 0;
        for (0..params.toy.ell) |i| {
            const w = torus.gadgetWeight(params.toy.bg_bits, i);
            acc_a +%= d[i].c[j] *% w;
            acc_b +%= d[params.toy.ell + i].c[j] *% w;
        }
        try testing.expect(@min(acc_a -% ct.a.c[j], ct.a.c[j] -% acc_a) <= bound);
        try testing.expect(@min(acc_b -% ct.b.c[j], ct.b.c[j] -% acc_b) <= bound);
    }
}

test "gate flag ON: the four cores are implemented" {
    try testing.expect(gate.fable_core_implemented);
}
