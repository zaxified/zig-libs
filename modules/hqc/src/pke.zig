// SPDX-License-Identifier: MIT
//! pke — HQC's public-key encryption scheme (spec §3.5; reference
//! `src/ref/hqc.c`'s `hqc_pke_keygen`/`hqc_pke_encrypt`/`hqc_pke_decrypt`
//! + `src/ref/parsing.c`'s `hqc_ek_pke_from_string`/`hqc_dk_pke_from_string`).
//!
//! **This is pure composition over Parts 1-2** (`gf2x.Ring`, `prng`'s
//! samplers/hashes, `code.Code`'s encode/decode) — no new algorithm, only
//! the wiring the spec's §3.5 keygen/encrypt/decrypt algorithms specify.
//! Every step below is a direct, byte-layout-faithful port of the
//! corresponding reference C function; see each function's doc comment
//! for the line-by-line correspondence.
//!
//! **Key insight this module encodes**: the decryption key never stores
//! `x`, only `seed_dk` (32 bytes) — see `keygen`'s doc. `y` (the only
//! secret vector decrypt needs) is *re-derived* from `seed_dk` on every
//! `decrypt` call via the same fixed-weight sampler keygen used, which is
//! why `dkParse` mirrors `keygen`'s `y`-sampling exactly (first draw off
//! a fresh `Xof(seed_dk)` context) and never touches the second (`x`)
//! draw.

const std = @import("std");
const params = @import("params.zig");
const gf2x = @import("gf2x.zig");
const prng = @import("prng.zig");
const code = @import("code.zig");

/// The HQC-PKE scheme for one parameter set. `generator` is the matching
/// Reed-Solomon generator polynomial (`reedsolomon.generator_hqc1xx`),
/// threaded through to `code.Code` exactly as `code.zig` requires.
pub fn Pke(comptime p: params.Params, comptime generator: [2 * p.delta + 1]u8) type {
    return struct {
        pub const Ring = gf2x.Ring(p.n);
        pub const Code = code.Code(p, generator);
        pub const Message = Code.Message;

        /// |ek_pke| = |seed| + ceil(n/8) (spec §3.5's keypair format;
        /// `PUBLIC_KEY_BYTES` in the reference, since HQC-KEM's ek is
        /// literally ek_pke — see kem.zig).
        pub const ek_bytes = p.ekBytes();
        /// |dk_pke| = |seed| ONLY — see module doc: `x` is generated
        /// during keygen but discarded, never serialized (`hqc_pke_
        /// keygen`'s `dk_pke` buffer is `memcpy(dk_pke, seed_dk,
        /// SEED_BYTES)`, nothing else).
        pub const dk_bytes = params.seed_bytes;

        pub const EncKey = [ek_bytes]u8;
        pub const DecKey = [dk_bytes]u8;

        /// PKE ciphertext (spec §3.5's `(u, v)`; reference's
        /// `ciphertext_pke_t`). `u` lives in the full ring (n bits); `v`
        /// is already truncated to n1n2 bits (the codeword width) by
        /// construction — see `encrypt`.
        pub const Ciphertext = struct {
            u: Ring.Elem,
            v: Code.Codeword,
        };

        pub const KeyPair = struct { ek: EncKey, dk: DecKey };

        /// hqc_pke_keygen: `seed` (32 B, this is HQC-KEM's `seed_pke`) ->
        /// (ek_pke, dk_pke).
        ///
        ///   keypair_seed = I(seed) = seed_dk(32) || seed_ek(32)
        ///   (y, x) = SampleFixedWeightVect$(Xof(seed_dk)), CHAINED: y
        ///            first, then x on the SAME Xof context (reference:
        ///            `vect_sample_fixed_weight1(&dk_xof_ctx, y, ...)`
        ///            then `..., x, ...)` — the order matters for byte-
        ///            exactness, see prng.zig's `Xof.getBytes` doc).
        ///   h = SampleVect(Xof(seed_ek))
        ///   s = y*h + x
        ///   ek_pke = seed_ek || s
        ///   dk_pke = seed_dk
        pub fn keygen(seed: *const [params.seed_bytes]u8) KeyPair {
            var keypair_seed: [64]u8 = undefined;
            prng.hashI(&keypair_seed, seed);
            const seed_dk = keypair_seed[0..params.seed_bytes];
            const seed_ek = keypair_seed[params.seed_bytes..64];

            var dk_xof = prng.Xof.init(seed_dk);
            var y_support: [p.omega]u32 = undefined;
            prng.sampleFixedWeightRejection(&dk_xof, p.n, p.nMu(), p.rejectionThreshold(), p.omega, &y_support);
            var y = Ring.zero;
            prng.writeSupportToVector(p.omega, &y_support, &y);

            // x continues the SAME Xof context (not re-initialized) —
            // see module doc.
            var x_support: [p.omega]u32 = undefined;
            prng.sampleFixedWeightRejection(&dk_xof, p.n, p.nMu(), p.rejectionThreshold(), p.omega, &x_support);
            var x = Ring.zero;
            prng.writeSupportToVector(p.omega, &x_support, &x);

            var ek_xof = prng.Xof.init(seed_ek);
            var h = Ring.zero;
            prng.sampleVect(&ek_xof, p.n, &h);

            const s = Ring.add(Ring.mul(y, h), x);

            var ek: EncKey = undefined;
            @memcpy(ek[0..params.seed_bytes], seed_ek);
            Ring.toBytes(s, ek[params.seed_bytes..]);

            var dk: DecKey = undefined;
            @memcpy(&dk, seed_dk);

            return .{ .ek = ek, .dk = dk };
        }

        /// hqc_ek_pke_from_string: re-derive (h, s) from a serialized
        /// ek_pke. `h` is re-sampled from the embedded seed_ek (NOT
        /// stored directly — only `s` is stored as raw bytes).
        fn ekParse(ek: EncKey) struct { h: Ring.Elem, s: Ring.Elem } {
            var ek_xof = prng.Xof.init(ek[0..params.seed_bytes]);
            var h = Ring.zero;
            prng.sampleVect(&ek_xof, p.n, &h);
            const s = Ring.fromBytes(ek[params.seed_bytes..]);
            return .{ .h = h, .s = s };
        }

        /// hqc_dk_pke_from_string: re-derive `y` (and only `y` — see
        /// module doc) from a serialized dk_pke.
        fn dkParse(dk: DecKey) Ring.Elem {
            var dk_xof = prng.Xof.init(&dk);
            var y_support: [p.omega]u32 = undefined;
            prng.sampleFixedWeightRejection(&dk_xof, p.n, p.nMu(), p.rejectionThreshold(), p.omega, &y_support);
            var y = Ring.zero;
            prng.writeSupportToVector(p.omega, &y_support, &y);
            return y;
        }

        /// truncate(v) to n1n2 bits, then return its first
        /// `Code.codeword_len` bytes (the packed n1n2-bit prefix) — the
        /// spec's `Truncate` composed with the byte view `code.zig`'s
        /// codeword needs. Shared by `encrypt`'s `s.r2 + e` term and
        /// `decrypt`'s `u.y` term (reference's `vect_truncate` +
        /// implicit byte-array reinterpretation, both call sites).
        fn truncatedBytes(v: Ring.Elem) [Code.codeword_len]u8 {
            var t = v;
            Ring.truncate(&t, p.n1n2());
            var full: [Ring.n_bytes]u8 = undefined;
            Ring.toBytes(t, &full);
            var out: [Code.codeword_len]u8 = undefined;
            @memcpy(&out, full[0..Code.codeword_len]);
            return out;
        }

        /// hqc_pke_encrypt: `theta` (32 B) -> (r1, r2, e), then:
        ///
        ///   u = r2*h + r1
        ///   v = C.encode(m) + Truncate(s*r2 + e)
        ///
        /// Sampling order off the SAME theta-Xof context is r2, e, r1
        /// (reference: `vect_sample_fixed_weight2(ctx, r2, OMEGA_R)`
        /// then `..., e, OMEGA_E)` then `..., r1, OMEGA_R)` — OMEGA_E ==
        /// OMEGA_R for every HQC parameter set, see params.zig's
        /// `omega_r` field doc).
        pub fn encrypt(ek: EncKey, m: Message, theta: *const [params.seed_bytes]u8) Ciphertext {
            var theta_xof = prng.Xof.init(theta);
            const parsed = ekParse(ek);

            var r2_support: [p.omega_r]u32 = undefined;
            prng.sampleFixedWeightBiased(&theta_xof, p.n, p.omega_r, &r2_support);
            var r2 = Ring.zero;
            prng.writeSupportToVector(p.omega_r, &r2_support, &r2);

            var e_support: [p.omega_r]u32 = undefined;
            prng.sampleFixedWeightBiased(&theta_xof, p.n, p.omega_r, &e_support);
            var e = Ring.zero;
            prng.writeSupportToVector(p.omega_r, &e_support, &e);

            var r1_support: [p.omega_r]u32 = undefined;
            prng.sampleFixedWeightBiased(&theta_xof, p.n, p.omega_r, &r1_support);
            var r1 = Ring.zero;
            prng.writeSupportToVector(p.omega_r, &r1_support, &r1);

            const u = Ring.add(Ring.mul(r2, parsed.h), r1);

            const sr2_plus_e = Ring.add(Ring.mul(r2, parsed.s), e);
            const trunc_bytes = truncatedBytes(sr2_plus_e);

            const enc_m = Code.encode(m);
            var v: Code.Codeword = undefined;
            for (&v, enc_m, trunc_bytes) |*o, a, b| o.* = a ^ b;

            return .{ .u = u, .v = v };
        }

        /// hqc_pke_decrypt: `m = C.decode(v - Truncate(u*y))` (spec
        /// §3.5). Over F2, subtraction is XOR, same as addition.
        pub fn decrypt(dk: DecKey, ct: Ciphertext) Message {
            const y = dkParse(dk);
            const uy = Ring.mul(y, ct.u);
            const trunc_bytes = truncatedBytes(uy);

            var tmp2: Code.Codeword = undefined;
            for (&tmp2, ct.v, trunc_bytes) |*o, a, b| o.* = a ^ b;

            return Code.decode(tmp2);
        }
    };
}
