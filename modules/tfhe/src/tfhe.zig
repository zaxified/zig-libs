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
//! ## The Fable core — `gate.fable_core_implemented` (now `true`, IMPLEMENTED)
//!   - `externalProduct` (GGSW ⊠ GLWE), `cmux`, `blindRotate`, `bootstrap` — all
//!     real; no `@panic` remains behind the gate.
//!
//! ## Randomness — a security contract, not a portability tag
//!
//! Every production key-generation and encryption entry point takes
//! `io: std.Io` and draws through `entropy.SecureSource`, the fail-closed
//! `std.Random` adapter over `std.Io.randomSecure` (`modules/entropy`) — not
//! `std.Random.IoSource`, which binds `std.Io.random`. `std.Io.random` is
//! **contractually a CSPRNG** (`std/Io.zig`: "Obtains entropy from a
//! cryptographically secure pseudo-random number generator") but that same
//! doc comment documents a silent fallback to a weaker seed if the CSPRNG
//! source fails; the default `Io.Threaded` falls back to a pid+clock+ASLR
//! seed when `getrandom(2)` fails, e.g. under a seccomp policy that blocks
//! it. A bare `std.Random` parameter would
//! be worse still — it would accept `DefaultPrng.init(0)` at a call site that
//! looks identical to a correct one — and either failure mode here does not
//! weaken this scheme, it removes it. With `e` and `a` predictable,
//! `b = ⟨a,s⟩ + μ + e` is a linear system: `dim` ciphertexts recover the
//! secret key `s` by Gaussian elimination. The bootstrap and key-switch keys
//! are GLWE/GGSW encryptions of that same key and are *published* to the
//! evaluator, so predictable masking there hands the key over directly.
//! `entropy.SecureSource` aborts the process rather than draw from a source
//! that degraded — see its doc comment for why that is the right trade at a
//! `void`-returning `std.Random.fillFn`.
//!
//! The `…ForTest` twins keep a `std.Random` parameter, because the draw→value
//! KATs at the bottom of this file and the seeded end-to-end tests must stay
//! reproducible. They are named so that a production call site cannot use one
//! by accident. Taking `std.Io` (rather than reading OS entropy directly) keeps
//! the module `platform = .any`, the same shape `bbs`/`ibe`/`tlock` use.
//! Failing closed via `std.Io.randomSecure` was an open, tracked decision
//! (B7); it is now closed (`CONVENTIONS.md` §2.2), and this module takes it.
//!
//! ## Constant-time posture (key path)
//!
//! `sampleBit`, and therefore `lweKeyGen`/`glweKeyGen`, are **fixed-cost and
//! branch-free**: one `u32` draw per key bit, the bit read arithmetically, no
//! rejection loop. `sampleError` likewise consumes exactly one 64-bit draw.
//! `clearBootstrap` selects on the secret key bit with a mask rather than an
//! `if`. See each function for what changed and why.
//!
//! This is **source-level** constant time. It is not verified codegen — the
//! compiler is free to reintroduce a branch — and no timing measurement was
//! taken. `gadget.decompose` still branches, but only ever on ciphertext
//! coefficients, never on key material.

const std = @import("std");
const builtin = @import("builtin");
const entropy = @import("entropy");
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
            return struct {
                s: [dim]T,

                /// Securely wipe the secret key. Fixed-size, no heap — zeroing
                /// the struct's bytes erases the secret bits `s`. Call when
                /// the key is no longer needed; left zeroed, must not be
                /// reused. Idempotent.
                pub fn deinit(self: *@This()) void {
                    std.crypto.secureZero(u8, std.mem.asBytes(self));
                }
            };
        }
        /// Input/output LWE (under the small key `s ∈ {0,1}^n`).
        pub const LweN = Lwe(n);
        /// LWE extracted from a GLWE (under the "big" key `s_ext ∈ {0,1}^{kN}`).
        pub const LweBig = Lwe(N);

        /// GLWE (`k=1`) secret key: one binary polynomial.
        pub const GlweKey = struct {
            s: Poly,

            /// Securely wipe the secret key. Fixed-size, no heap — zeroing
            /// the struct's bytes erases the secret polynomial `s`. Call
            /// when the key is no longer needed; left zeroed, must not be
            /// reused. Idempotent.
            pub fn deinit(self: *GlweKey) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
            }
        };
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
        pub const BootstrapKey = struct {
            ggsw: [n]Ggsw,

            /// Securely wipe the bootstrap key. Each row is an ENCRYPTION of
            /// a secret bit (not the bit itself), so this is defense-in-depth
            /// rather than a bare-secret erasure — still handled with the
            /// same discipline as the raw `LweKey`/`GlweKey` it is built
            /// from. Fixed-size, no heap. Idempotent.
            pub fn deinit(self: *BootstrapKey) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
            }
        };

        /// Key-switch key: for each big-key coordinate `j` and gadget level `i`,
        /// an `LweN` encryption of `s_ext[j]·q/B_ks^{i+1}` under the small key.
        pub const KeySwitchKey = struct {
            rows: [N][ell_ks]LweN,

            /// Securely wipe the key-switch key. Each row is an ENCRYPTION of
            /// a big-key coordinate (not the coordinate itself), so this is
            /// defense-in-depth rather than a bare-secret erasure. Fixed-size,
            /// no heap. Idempotent.
            pub fn deinit(self: *KeySwitchKey) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
            }
        };

        pub fn init() !Self {
            try P.validate();
            return .{};
        }

        // ── samplers (caller-supplied RNG) ───────────────────────────────────

        /// One secret key bit. **Fixed-cost and branch-free.**
        ///
        /// The previous body was `random.uintLessThan(u32, 2)`, which is
        /// `std.Random`'s Lemire sampler: it computes a rejection threshold
        /// and then *branches on the drawn value*, and its own doc-comment
        /// says "the runtime of this function is exponentially distributed".
        /// The drawn value is the secret key bit, so that is a branch on a
        /// secret.
        ///
        /// For `less_than = 2` the threshold reduces to 0 (`-%2`, minus 2,
        /// then `% 2`), so the loop provably cannot run and the returned value
        /// is exactly `m >> 32 = x >> 31` — the top bit of the single `u32`
        /// draw. Taking that bit directly is therefore **bit-identical** to
        /// the old sampler (the KATs at the bottom of this file were written
        /// against the old one and did not change), while having no branch and
        /// no data-dependent draw count at all.
        fn sampleBit(random: std.Random) T {
            return random.int(u32) >> 31;
        }

        /// The quantile map from a uniform 64-bit draw to an error in
        /// `[−B, B]`. Split out from `sampleError` so a test can compare it
        /// against the pre-rewrite 32-bit map on the same quantile.
        ///
        /// Multiply-shift, not rejection: `v = ⌊u·(2B+1)/2^64⌋`. Fixed cost,
        /// no branch, no loop.
        fn errorFromUniform(u: u64) T {
            comptime std.debug.assert(B < (1 << 30));
            const span: u64 = 2 * @as(u64, B) + 1;
            const v: u64 = @intCast((@as(u128, u) * span) >> 64);
            const e: i32 = @as(i32, @intCast(v)) - @as(i32, @intCast(B));
            return @bitCast(e);
        }

        /// Error uniform in `[−B, B]`, as a torus element (two's complement).
        /// **Fixed-cost**: exactly one 64-bit draw, always.
        ///
        /// The previous body was `random.intRangeAtMost(i32, −B, B)`, which
        /// routes through `std.Random.uintLessThan` and inherits the same
        /// rejection loop — and here the rejection probability is not
        /// vanishing by construction the way it is for a single bit: it is
        /// `t/2^32` with `t = 2^32 mod (2B+1)`. `std.Random` ships the
        /// fixed-cost `…Biased` variants for exactly this situation.
        ///
        /// We do the multiply-shift at **64** bits rather than calling the
        /// 32-bit `uintLessThanBiased`, because the residual bias of a
        /// multiply-shift is one part in `2^bits/span`: `≈2^-21` in
        /// statistical distance from a 32-bit draw, `≈2^-53` from a 64-bit
        /// one. Trading an unbiased-but-variable-time sampler for a
        /// `2^-21`-biased constant-time one would have been a bad deal for a
        /// noise distribution; `2^-53` is not.
        fn sampleError(random: std.Random) T {
            return errorFromUniform(random.int(u64));
        }

        /// Bytes of `std.Random` one error sample consumes. A CONSTANT, not an
        /// average — that is the whole point of the rewrite, and the KAT below
        /// asserts the byte counter lands exactly on `draws · this`.
        pub const error_draw_bytes: usize = 8;
        /// Test-visible aliases: the samplers are private, but the KATs that
        /// pin the draw→value mapping have to reach them.
        pub const sampleErrorForTest = sampleError;
        pub const errorFromUniformForTest = errorFromUniform;

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
        //
        // Every randomness-consuming entry point in this file exists twice:
        //
        //   - `f(…, io: std.Io)`               — PRODUCTION. Draws through
        //     `entropy.SecureSource`, fail-closed on `std.Io.randomSecure`
        //     (aborts rather than falling back to the weaker seed
        //     `std.Random.IoSource`/`std.Io.random` would silently accept).
        //   - `fForTest(…, random: std.Random)` — TEST/KAT ONLY. Reproducible
        //     draws for the KATs and the seeded end-to-end tests. Never call
        //     one of these from production code; the name is the signal.
        //
        // See the module doc comment for what a predictable stream actually
        // costs (it does not weaken the scheme, it removes it).

        /// Generate a binary LWE secret key of dimension `dim` — the module's
        /// most sensitive value — with every bit drawn from `io`'s CSPRNG.
        ///
        /// `io` must be a real `std.Io`: the draw goes through
        /// `entropy.SecureSource`, fail-closed on `std.Io.randomSecure`. If the
        /// bits were drawn from a seeded PRNG
        /// the key would be a deterministic function of that seed: anyone who
        /// guesses it, or reads it out of the consumer's binary, decrypts every
        /// ciphertext the deployment ever produced. That is why this takes
        /// `std.Io` and `lweKeyGenForTest` — which takes anything — is named
        /// the way it is.
        pub fn lweKeyGen(comptime dim: usize, io: std.Io) LweKey(dim) {
            var src: entropy.SecureSource = .{ .io = io };
            return lweKeyGenForTest(dim, src.interface());
        }

        /// TEST/KAT ONLY — `lweKeyGen` with caller-chosen draws, so the
        /// draw→key-bit mapping can be frozen by a KAT and the end-to-end tests
        /// stay reproducible. A `std.Random` here may be `DefaultPrng.init(0)`,
        /// which as a *key* source is equivalent to publishing the key.
        pub fn lweKeyGenForTest(comptime dim: usize, random: std.Random) LweKey(dim) {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            var key: LweKey(dim) = undefined;
            for (&key.s) |*x| x.* = sampleBit(random);
            return key;
        }

        /// Generate the binary GLWE secret key (one polynomial) from `io`'s
        /// CSPRNG. Same contract and same stakes as `lweKeyGen`: this key is
        /// what the accumulator and every GGSW row are encrypted under, and
        /// `extractGlweKey` reads its coefficients out as a plain LWE key, so a
        /// seeded stream here compromises the whole bootstrapping pipeline.
        pub fn glweKeyGen(io: std.Io) GlweKey {
            var src: entropy.SecureSource = .{ .io = io };
            return glweKeyGenForTest(src.interface());
        }

        /// TEST/KAT ONLY — see `lweKeyGenForTest`.
        pub fn glweKeyGenForTest(random: std.Random) GlweKey {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
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

        /// Encrypt an already-scaled torus message `μ` under `key`, drawing the
        /// mask `a` and the noise `e` from `io`'s CSPRNG.
        ///
        /// `io` must be a real `std.Io`. Both halves of the ciphertext come off
        /// one stream, so if that stream is predictable then `a` and `e` are
        /// known to the attacker and `b − ⟨a,s⟩ = μ + e` is a linear equation
        /// in `s` with no unknown noise left: `dim` such ciphertexts recover
        /// `s` by Gaussian elimination. Predictable noise is not a weakened LWE
        /// instance, it is no LWE instance.
        pub fn lweEncrypt(comptime dim: usize, key: *const LweKey(dim), mu: T, io: std.Io) Lwe(dim) {
            var src: entropy.SecureSource = .{ .io = io };
            return lweEncryptForTest(dim, key, mu, src.interface());
        }

        /// TEST/KAT ONLY — `lweEncrypt` with caller-chosen draws.
        pub fn lweEncryptForTest(comptime dim: usize, key: *const LweKey(dim), mu: T, random: std.Random) Lwe(dim) {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
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

        /// Encrypt an already-scaled plaintext polynomial `μ`: `b = a·s + μ + e`,
        /// with the mask polynomial `a` and the noise polynomial `e` drawn from
        /// `io`'s CSPRNG.
        ///
        /// `io` must be a real `std.Io`. The ring version of `lweEncrypt`'s
        /// failure is worse, not better: one GLWE ciphertext carries `N`
        /// coefficient equations, so a single ciphertext under a predictable
        /// stream is already an `N`-equation linear system in the `N`
        /// coefficients of the GLWE key.
        pub fn glweEncrypt(key: *const GlweKey, msg: *const Poly, io: std.Io) Glwe {
            var src: entropy.SecureSource = .{ .io = io };
            return glweEncryptForTest(key, msg, src.interface());
        }

        /// TEST/KAT ONLY — `glweEncrypt` with caller-chosen draws.
        pub fn glweEncryptForTest(key: *const GlweKey, msg: *const Poly, random: std.Random) Glwe {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const a = sampleUniformPoly(random);
            var b = a.mul(&key.s);
            b.addAssign(msg);
            const e = sampleErrorPoly(random);
            b.addAssign(&e);
            return .{ .a = a, .b = b };
        }

        /// Fresh encryption of the zero polynomial from `io`'s CSPRNG — the
        /// masking term every GGSW row is built on (see `ggswEncryptPoly`).
        /// `io` must be a real `std.Io`: a GLWE(0) whose `a` and `e` are
        /// predictable masks nothing at all, so every row that adds a gadget
        /// term to it publishes that term in the clear.
        pub fn glweEncryptZero(key: *const GlweKey, io: std.Io) Glwe {
            var src: entropy.SecureSource = .{ .io = io };
            return glweEncryptZeroForTest(key, src.interface());
        }

        /// TEST/KAT ONLY — `glweEncryptZero` with caller-chosen draws.
        pub fn glweEncryptZeroForTest(key: *const GlweKey, random: std.Random) Glwe {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const z = Poly.zero();
            return glweEncryptForTest(key, &z, random);
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

        /// Encrypt a message polynomial `μ` as a GGSW (gadget matrix) from
        /// `io`'s CSPRNG. Each row is a fresh GLWE(0) plus the gadget term
        /// `μ·q/B_g^{i+1}` in the component the block selects.
        ///
        /// `io` must be a real `std.Io`. GGSW is where the stakes are highest:
        /// the messages this module encrypts as GGSW are the LWE secret key
        /// bits themselves (`bootstrapKeyGen`), and the resulting key is
        /// *published* to whoever evaluates the circuit. Predictable row masks
        /// therefore do not merely leak a plaintext, they hand over the key.
        pub fn ggswEncryptPoly(key: *const GlweKey, msg: *const Poly, io: std.Io) Ggsw {
            var src: entropy.SecureSource = .{ .io = io };
            return ggswEncryptPolyForTest(key, msg, src.interface());
        }

        /// TEST/KAT ONLY — `ggswEncryptPoly` with caller-chosen draws.
        pub fn ggswEncryptPolyForTest(key: *const GlweKey, msg: *const Poly, random: std.Random) Ggsw {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            var g: Ggsw = undefined;
            for (0..ell) |i| {
                const w = torus.gadgetWeight(bg_bits, i);
                const scaled = msg.scalarMul(w);
                // block A: gadget term in mask component `a`.
                var ra = glweEncryptZeroForTest(key, random);
                ra.a.addAssign(&scaled);
                g.rows[i] = ra;
                // block B: gadget term in body component `b`.
                var rb = glweEncryptZeroForTest(key, random);
                rb.b.addAssign(&scaled);
                g.rows[ell + i] = rb;
            }
            return g;
        }

        /// GGSW of a scalar (constant polynomial), e.g. a secret key bit, from
        /// `io`'s CSPRNG. `io` must be a real `std.Io` — see
        /// `ggswEncryptPoly` for what a predictable stream costs here.
        pub fn ggswEncryptScalar(key: *const GlweKey, m: T, io: std.Io) Ggsw {
            var src: entropy.SecureSource = .{ .io = io };
            return ggswEncryptScalarForTest(key, m, src.interface());
        }

        /// TEST/KAT ONLY — `ggswEncryptScalar` with caller-chosen draws.
        pub fn ggswEncryptScalarForTest(key: *const GlweKey, m: T, random: std.Random) Ggsw {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const c = Poly.constant(m);
            return ggswEncryptPolyForTest(key, &c, random);
        }

        /// Bootstrap key: `GGSW(s_i)` for each LWE secret bit, under the GLWE
        /// key, with every row's masking drawn from `io`'s CSPRNG.
        ///
        /// `io` must be a real `std.Io`. This key is the one a deployment ships
        /// to the evaluator, and its rows encrypt the LWE secret key bit by
        /// bit: with a predictable stream the evaluator (or anyone who sees the
        /// key) subtracts the known masks and reads `s` off directly — no
        /// lattice problem is involved.
        pub fn bootstrapKeyGen(lwe_key: *const LweKey(n), glwe_key: *const GlweKey, io: std.Io) BootstrapKey {
            var src: entropy.SecureSource = .{ .io = io };
            return bootstrapKeyGenForTest(lwe_key, glwe_key, src.interface());
        }

        /// TEST/KAT ONLY — `bootstrapKeyGen` with caller-chosen draws.
        pub fn bootstrapKeyGenForTest(lwe_key: *const LweKey(n), glwe_key: *const GlweKey, random: std.Random) BootstrapKey {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            var bsk: BootstrapKey = undefined;
            for (0..n) |i| bsk.ggsw[i] = ggswEncryptScalarForTest(glwe_key, lwe_key.s[i], random);
            return bsk;
        }

        /// Key-switch key from the big (extracted) GLWE key to the small LWE
        /// key, with every row encrypted from `io`'s CSPRNG.
        ///
        /// `io` must be a real `std.Io`. Each row is an LWE encryption of a
        /// gadget multiple of a *big-key coordinate*, so this key too is a
        /// published encryption of secret material: predictable masks turn its
        /// `N·ℓ_ks` rows into a solved linear system for the GLWE key.
        pub fn keySwitchKeyGen(glwe_key: *const GlweKey, small_key: *const LweKey(n), io: std.Io) KeySwitchKey {
            var src: entropy.SecureSource = .{ .io = io };
            return keySwitchKeyGenForTest(glwe_key, small_key, src.interface());
        }

        /// TEST/KAT ONLY — `keySwitchKeyGen` with caller-chosen draws.
        pub fn keySwitchKeyGenForTest(glwe_key: *const GlweKey, small_key: *const LweKey(n), random: std.Random) KeySwitchKey {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const big = extractGlweKey(glwe_key);
            var ksk: KeySwitchKey = undefined;
            for (0..N) |j| {
                for (0..ell_ks) |i| {
                    const msg = big.s[j] *% torus.gadgetWeight(bks_bits, i);
                    ksk.rows[j][i] = lweEncryptForTest(n, small_key, msg, random);
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
        /// Constant-time in the same sense as the rest of the key path: the
        /// accumulation used to read `if (si == 1)`, a branch on a secret key
        /// bit. It is now an arithmetic select — `sel` is all-ones iff
        /// `si == 1` — so the loop runs the same instructions for every key.
        /// `two_n` is a comptime power of two, so `% two_n` is a mask.
        pub fn clearBootstrap(lut: *const Poly, ct: *const LweN, key: *const LweKey(n)) T {
            var rot: usize = (two_n - (modSwitchScalar(ct.b) % two_n)) % two_n; // X^{−b̃}
            for (ct.a, key.s) |ai, si| {
                const sel: usize = 0 -% @as(usize, si & 1);
                rot = (rot + (modSwitchScalar(ai) & sel)) % two_n;
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
        /// `u32` polynomials, and `Poly.mul` is exact mod `2^32` on both of its
        /// paths (schoolbook and integer NTT are bit-identical), so
        /// signed×torus products need no special handling.
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
    const key = Toy.lweKeyGenForTest(64, rnd);
    for (0..50) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &key, Toy.encodeBit(b), rnd);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &key, &ct));
    }
}

test "GLWE encrypt/decrypt round-trips a scaled plaintext" {
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    const key = Toy.glweKeyGenForTest(rnd);
    // plaintext: Δ·(coefficient bits)
    var msg = Toy.Poly.zero();
    for (&msg.c, 0..) |*c, i| c.* = Toy.encodeBit(@intCast(i & 1));
    const ct = Toy.glweEncryptForTest(&key, &msg, rnd);
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
    const gk = Toy.glweKeyGenForTest(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    for (0..20) |_| {
        const b0 = rnd.uintLessThan(u32, 2);
        var msg = Toy.Poly.zero();
        msg.c[0] = Toy.encodeBit(b0);
        // fill other coeffs with arbitrary scaled bits (must NOT leak into coeff 0)
        for (msg.c[1..]) |*c| c.* = Toy.encodeBit(rnd.uintLessThan(u32, 2));
        const ct = Toy.glweEncryptForTest(&gk, &msg, rnd);
        const lwe = Toy.sampleExtract(&ct);
        try testing.expectEqual(b0, Toy.lweDecryptBit(N_big, &big_key, &lwe));
    }
}
const N_big = params.toy.N;

test "keySwitch preserves the message (big key → small key)" {
    var prng = std.Random.DefaultPrng.init(4);
    const rnd = prng.random();
    const gk = Toy.glweKeyGenForTest(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    const small_key = Toy.lweKeyGenForTest(64, rnd);
    const ksk = Toy.keySwitchKeyGenForTest(&gk, &small_key, rnd);
    for (0..20) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct_big = Toy.lweEncryptForTest(N_big, &big_key, Toy.encodeBit(b), rnd);
        const ct_small = Toy.keySwitch(&ksk, &ct_big);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &small_key, &ct_small));
    }
}

test "decomposeGlwe recomposes each component within the gadget error bound" {
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    const gk = Toy.glweKeyGenForTest(rnd);
    const ct = Toy.glweEncryptZeroForTest(&gk, rnd);
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

// ── the draw→secret mapping, pinned ──────────────────────────────────────────
//
// Nothing in this module pinned WHICH bit of a `std.Random` draw becomes a key
// bit, so a sampler rewrite could have swapped its arms and every existing test
// would still have passed — the key distribution stays uniform either way, and
// encrypt/decrypt round-trips under whatever key it produced. These KATs close
// that hole. They were written and run GREEN against the pre-CT samplers first,
// and are unchanged by the constant-time rewrite: that is the evidence the
// rewrite changed the *cost* of sampling and not the *result*.

/// A `std.Random` returning a fixed, formula-generated byte stream:
/// `byte(j) = ((j · 0x9E3779B1 mod 2^32) >> 11) & 0xFF`. Reproducible in any
/// language, so the frozen vectors below were derived independently rather
/// than captured from this module's own output. It also COUNTS the bytes it
/// hands out — which is how the tests observe that sampling is fixed-cost.
const ScriptedRandom = struct {
    pos: usize = 0,

    fn byteAt(j: usize) u8 {
        const x: u32 = @truncate(@as(u64, j) *% 0x9E3779B1);
        return @truncate(x >> 11);
    }
    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *ScriptedRandom = @ptrCast(@alignCast(ptr));
        for (buf) |*b| {
            b.* = byteAt(self.pos);
            self.pos += 1;
        }
    }
    fn random(self: *ScriptedRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

fn bitOfHex(frozen: []const u8, i: usize) u32 {
    return (frozen[i / 8] >> @intCast(7 - (i % 8))) & 1;
}

test "KAT: lweKeyGen's draw→key-bit mapping (frozen) and its fixed cost" {
    var frozen: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&frozen, "c99999b333366666");

    var sc: ScriptedRandom = .{};
    const key = Toy.lweKeyGenForTest(64, sc.random());
    for (0..64) |i| {
        try testing.expectEqual(bitOfHex(&frozen, i), key.s[i]);
        // Independent derivation: bit `i` is the TOP bit of the little-endian
        // `u32` of draw `i`, i.e. the high bit of that draw's 4th byte.
        try testing.expectEqual(@as(u32, ScriptedRandom.byteAt(4 * i + 3) >> 7), key.s[i]);
    }
    // Exactly four bytes per key bit — no rejection loop drew a fifth. This is
    // the observable a data-dependent sampler would break.
    try testing.expectEqual(@as(usize, 4 * 64), sc.pos);
}

test "KAT: glweKeyGen's draw→key-bit mapping (frozen) and its fixed cost" {
    var frozen: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &frozen,
        "c99999b3333666664ccccd9999b3333266666ccccd999993333366666ccccc99",
    );
    var sc: ScriptedRandom = .{};
    const gk = Toy.glweKeyGenForTest(sc.random());
    for (0..N_big) |i| {
        try testing.expectEqual(bitOfHex(&frozen, i), gk.s.c[i]);
        try testing.expectEqual(@as(u32, ScriptedRandom.byteAt(4 * i + 3) >> 7), gk.s.c[i]);
    }
    try testing.expectEqual(@as(usize, 4 * N_big), sc.pos);
}

test "sampled key bits really are bits, and both keygens agree bit-for-bit" {
    // `lweKeyGen(N)` and `glweKeyGen` must sample the SAME way — the GLWE key
    // is read back out as an LWE key by `extractGlweKey`, so a divergence here
    // would be a silent scheme bug, not a style difference.
    var s1: ScriptedRandom = .{};
    var s2: ScriptedRandom = .{};
    const lk = Toy.lweKeyGenForTest(N_big, s1.random());
    const gk = Toy.glweKeyGenForTest(s2.random());
    try testing.expectEqualSlices(T, &lk.s, &gk.s.c);
    try testing.expectEqual(s1.pos, s2.pos);
    for (lk.s) |b| try testing.expect(b == 0 or b == 1);
}

test "KAT: the error sampler is fixed-cost and symmetric about zero" {
    var sc: ScriptedRandom = .{};
    var seen_neg = false;
    var seen_pos = false;
    const draws = 512;
    for (0..draws) |_| {
        const e: i32 = @bitCast(Toy.sampleErrorForTest(sc.random()));
        try testing.expect(e >= -@as(i32, @intCast(params.toy.err_bound)));
        try testing.expect(e <= @as(i32, @intCast(params.toy.err_bound)));
        if (e < 0) seen_neg = true;
        if (e > 0) seen_pos = true;
    }
    try testing.expect(seen_neg and seen_pos);
    // Fixed cost: exactly one draw per error, no rejection retry.
    try testing.expectEqual(@as(usize, draws * Toy.error_draw_bytes), sc.pos);
}

test "the error sampler's quantile map is unchanged, only its resolution" {
    // Unlike `sampleBit`, `sampleError` is NOT bit-identical to its old body:
    // it consumes 64 draw-bits instead of 32, so the same PRNG yields
    // different errors. That is a deliberate behaviour change and this test is
    // what stops it hiding an arm swap.
    //
    // The pre-rewrite map, written out here verbatim from `std.Random`'s
    // Lemire body (`uintLessThan(u32, 2B+1)` returns `⌊x·span/2^32⌋` whenever
    // it does not reject, and `intRangeAtMost` then adds `−B`):
    const B: u64 = params.toy.err_bound;
    const span: u64 = 2 * B + 1;
    const old = struct {
        fn map(x: u32, b: u64, sp: u64) i32 {
            const v: u64 = (@as(u64, x) * sp) >> 32;
            return @as(i32, @intCast(v)) - @as(i32, @intCast(b));
        }
    }.map;

    var prng = std.Random.DefaultPrng.init(909);
    const rnd = prng.random();
    for (0..20_000) |_| {
        const x = rnd.int(u32);
        // Same quantile, evaluated at 64-bit resolution, must give the SAME
        // value — the new map is the old map refined, not reflected.
        const got: i32 = @bitCast(Toy.errorFromUniformForTest(@as(u64, x) << 32));
        try testing.expectEqual(old(x, B, span), got);
    }
    // Endpoints and the sign convention, pinned by hand.
    try testing.expectEqual(-@as(i32, @intCast(B)), @as(i32, @bitCast(Toy.errorFromUniformForTest(0))));
    try testing.expectEqual(@as(i32, @intCast(B)), @as(i32, @bitCast(Toy.errorFromUniformForTest(std.math.maxInt(u64)))));
    // The midpoint draw is error 0 — a reflected sampler would still be
    // symmetric, but it would not fix these three points together with the
    // 20 000 quantile equalities above.
    try testing.expectEqual(@as(i32, 0), @as(i32, @bitCast(Toy.errorFromUniformForTest(1 << 63))));
}

test "deinit zeroes LWE/GLWE secret keys, bootstrap key, and key-switch key" {
    var prng = std.Random.DefaultPrng.init(6);
    const rnd = prng.random();

    var lwe_key = Toy.lweKeyGenForTest(64, rnd);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&lwe_key), 0));
    lwe_key.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&lwe_key), 0));

    var glwe_key = Toy.glweKeyGenForTest(rnd);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&glwe_key), 0));
    glwe_key.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&glwe_key), 0));

    const gk2 = Toy.glweKeyGenForTest(rnd);
    const small_key = Toy.lweKeyGenForTest(64, rnd);
    var bsk = Toy.bootstrapKeyGenForTest(&small_key, &gk2, rnd);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&bsk), 0));
    bsk.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&bsk), 0));

    var ksk = Toy.keySwitchKeyGenForTest(&gk2, &small_key, rnd);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&ksk), 0));
    ksk.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&ksk), 0));
}

// ── the RNG seam (B6) ────────────────────────────────────────────────────────

/// Type of a function's LAST parameter, or `null` if that parameter is itself
/// generic. Used by the seam test below to read a signature at comptime.
fn lastParamType(comptime F: type) ?type {
    const p = @typeInfo(F).@"fn".params;
    return p[p.len - 1].type;
}

test "RNG seam: every production keygen/encrypt takes std.Io, only the ForTest twins take std.Random" {
    // The point of this test is the SIGNATURE, not the value. `std.Random` is a
    // vtable — `DefaultPrng.init(0).random()` and a CSPRNG are indistinguishable
    // at a call site — so as long as a production entry point accepts one, a
    // consumer can silently generate an FHE secret key that is a function of a
    // seed. These entry points draw through `entropy.SecureSource`, fail-closed
    // on `std.Io.randomSecure` — not `std.Random.IoSource`, which would bind
    // the silently-degrading `std.Io.random`. If someone reintroduces a bare
    // `std.Random` parameter on any of these, this fails to compile or fails
    // here.
    inline for (.{
        @TypeOf(Toy.lweKeyGen), // generic in `dim`; the entropy parameter is still concrete
        @TypeOf(Toy.glweKeyGen),
        @TypeOf(Toy.lweEncrypt),
        @TypeOf(Toy.glweEncrypt),
        @TypeOf(Toy.glweEncryptZero),
        @TypeOf(Toy.ggswEncryptPoly),
        @TypeOf(Toy.ggswEncryptScalar),
        @TypeOf(Toy.bootstrapKeyGen),
        @TypeOf(Toy.keySwitchKeyGen),
    }) |F| {
        try testing.expect(lastParamType(F).? == std.Io);
        try testing.expect(lastParamType(F).? != std.Random);
    }
    // …and the reproducible twins keep `std.Random`, under a name a production
    // call site cannot use by accident.
    inline for (.{
        @TypeOf(Toy.lweKeyGenForTest),
        @TypeOf(Toy.glweKeyGenForTest),
        @TypeOf(Toy.lweEncryptForTest),
        @TypeOf(Toy.glweEncryptForTest),
        @TypeOf(Toy.glweEncryptZeroForTest),
        @TypeOf(Toy.ggswEncryptPolyForTest),
        @TypeOf(Toy.ggswEncryptScalarForTest),
        @TypeOf(Toy.bootstrapKeyGenForTest),
        @TypeOf(Toy.keySwitchKeyGenForTest),
    }) |F| {
        try testing.expect(lastParamType(F).? == std.Random);
    }
}

test "RNG seam: the std.Io path really draws entropy, and round-trips end to end" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A signature pin alone would pass over a body that ignores `io`. Two keys
    // drawn from the same `io` must differ: 64 independent bits each, so a
    // collision here is 2^-64 unless the entropy is not being read.
    const k1 = Toy.lweKeyGen(64, io);
    const k2 = Toy.lweKeyGen(64, io);
    try testing.expect(!std.mem.eql(T, &k1.s, &k2.s));
    const g1 = Toy.glweKeyGen(io);
    const g2 = Toy.glweKeyGen(io);
    try testing.expect(!std.mem.eql(T, &g1.s.c, &g2.s.c));

    // And the production path is a working path, not just a typed one.
    for (0..8) |b| {
        const bit: u32 = @intCast(b & 1);
        const ct = Toy.lweEncrypt(64, &k1, Toy.encodeBit(bit), io);
        try testing.expectEqual(bit, Toy.lweDecryptBit(64, &k1, &ct));
    }
    const msg = Toy.Poly.zero();
    const gct = Toy.glweEncrypt(&g1, &msg, io);
    for (Toy.glwePhase(&g1, &gct).c) |ph| {
        const err = @min(ph, 0 -% ph);
        try testing.expect(err <= params.toy.err_bound);
    }
}
