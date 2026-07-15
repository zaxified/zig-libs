// SPDX-License-Identifier: MIT
//! falcon — Falcon-512 and Falcon-1024 (FN-DSA, the NIST PQ lattice
//! signature; NTRU + fast-Fourier trapdoor sampling), pure Zig over
//! std.crypto's SHAKE256.
//!
//! **Implemented (and NIST-Round-3-KAT-verified byte-exactly), for both
//! parameter sets: signature VERIFICATION and all key/signature codecs.**
//! That is: public-key decode (14-bit packed h), secret-key decode
//! (trimmed f/g/F) plus the h = g*f^-1 mod q consistency recomputation,
//! compressed-signature decode/re-encode (canonical Golomb-Rice), SHAKE256
//! hash-to-point, negacyclic NTT over Z_q[x]/(x^n+1) with q = 12289
//! (n = 512 or 1024), and the s1 = c - s2*h short-vector norm check
//! (floor(beta^2) = 34034726 for n = 512, 70265242 for n = 1024 — see
//! `sig_bound` / `sig_bound_1024`). The KAT oracle is the official NIST
//! Round-3 submission package (FIPS 206 / FN-DSA is still a draft; Round-3
//! Falcon is the stable interop target) — `falcon512-KAT.rsp` and
//! `falcon1024-KAT.rsp` — see src/kat_vectors.zig.
//!
//! **Key generation and signing are SCAFFOLDED, not implemented**: the
//! public API (`generateKeyPair`, `signRandomized`, `signDeterministic` —
//! and their `_1024` counterparts), key/tree types, and KAT-harness
//! wiring (`kat_vectors.zig` now carries each vector's `seed`,
//! `keygen_sign_test.zig` calls the real API against them) are all real
//! and compile; the four genuinely hard pieces are `@panic("TODO(fable/
//! core): ...")` stubs (grep the module for that string):
//! `ntru.Ntru(Ring).generate` (NTRUGen/NTRUSolve — the tower-of-fields
//! big-integer machinery), `fft.Fft(Ring).fft`/`ifft` (the floating-point
//! FFT the sampler runs in), `ffsampling.buildTree`/`sampleSignature`
//! (ffLDL + the fast-Fourier nearest-plane recursion), and
//! `gaussian.samplerZ` (the discrete Gaussian sampler — see that file's
//! module doc comment: THE side-channel-critical primitive in this
//! module). A subtly wrong sampler still yields signatures that *verify*
//! while silently leaking the private key, so this ships as a scaffold
//! — structure and plumbing only — until the stubs can be filled in
//! KAT-exact AND constant-time. Also out of scope even once the stubs
//! are filled: the padded/CT signature format (the compressed format,
//! which the KATs use, is implemented) and any hardening beyond
//! `gaussian.samplerZ` itself (verification remains public-data-only and
//! needs none).
//!
//! Zig std GAP: yes — std.crypto ships ML-DSA and ML-KEM but no
//! Falcon/FN-DSA. Clean-room from the Falcon Round-3 specification
//! (public spec); the Round-3 reference implementation was consulted as a
//! wire-format/behavior design reference and KAT oracle — no source
//! ported — so it carries a design-reference NOTICE entry.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys are plain value types
    .model_after = "Falcon Round-3 spec (falcon-sign.info); NIST Round-3 KATs as oracle",
    .deps = .{}, // std only (SHAKE256)
};

/// Ring/modulus parameters and the NTT (q = 12289; n = 512 or 1024).
pub const poly = @import("poly.zig");

/// Wire encodings (modq / trimmed-i8 / compressed) + hash-to-point.
pub const codec = @import("codec.zig");

/// Floating-point FFT over the ring (signer-only). STUB — see module doc.
pub const fft = @import("fft.zig");
/// Discrete Gaussian sampler (SamplerZ, signer-only). STUB — see module
/// doc; the side-channel-critical primitive.
pub const gaussian = @import("gaussian.zig");
/// NTRU basis generation (NTRUGen/NTRUSolve, keygen-only). STUB.
pub const ntru = @import("ntru.zig");
/// LDL* tree + fast-Fourier nearest-plane sampling (ffSampling,
/// signer-only). STUB.
pub const ffsampling = @import("ffsampling.zig");
/// Key generation glue (real; delegates the hard math to `ntru` and
/// `ffsampling`).
pub const keygen = @import("keygen.zig");
/// Signing glue (real; delegates the hard math to `ffsampling`).
pub const sign = @import("sign.zig");

/// Nonce ("salt") length in every Falcon signature (both parameter sets).
pub const nonce_length = 40;

pub const VerifyError = error{
    /// Malformed signature: bad header, non-canonical compression,
    /// wrong length, or an sm envelope that does not parse.
    InvalidSignature,
    /// Well-formed signature that fails the lattice norm check.
    SignatureVerificationFailed,
};

/// One Falcon parameter set (n = 2^logn, q = 12289 always): the codecs,
/// `PublicKey`/`SecretKey` types, `verify`, and the NIST-envelope opener.
/// Instantiated below for logn = 9 (Falcon-512) and logn = 10
/// (Falcon-1024); `sig_bound_` is the spec's floor(beta^2) short-vector
/// acceptance bound for this degree.
fn Params(comptime logn_: u5, comptime sig_bound_: u64) type {
    return struct {
        const Self = @This();

        pub const Ring = poly.Ring(logn_);
        pub const Codec = codec.Codec(Ring);
        const n = Ring.n;

        /// Header byte of a compressed Falcon signature at this degree:
        /// 0x20 + logn.
        pub const sig_header: u8 = 0x20 + @as(u8, logn_);

        /// floor(beta^2) — inclusive bound on |(s1, s2)|^2 at this degree.
        pub const sig_bound: u64 = sig_bound_;

        /// A decoded Falcon public key (h and its cached NTT form).
        pub const PublicKey = struct {
            /// h in plain coefficient representation, coefficients in
            /// [0, q).
            h: Ring.Poly,
            /// NTT(h), cached for verification.
            h_ntt: Ring.Poly,

            pub const encoded_length = 1 + Codec.modq_encoded_len;

            /// Decode from the standard encoding: 0x00+logn header +
            /// 14-bit packed coefficients.
            pub fn fromBytes(bytes: *const [encoded_length]u8) error{InvalidPublicKey}!@This() {
                if (bytes[0] != 0x00 + @as(u8, logn_)) return error.InvalidPublicKey;
                var pk: @This() = undefined;
                Codec.modqDecode(&pk.h, bytes[1..]) catch return error.InvalidPublicKey;
                pk.h_ntt = pk.h;
                Ring.ntt(&pk.h_ntt);
                return pk;
            }

            /// Re-encode to the standard form.
            pub fn toBytes(pk: *const @This()) [encoded_length]u8 {
                var out: [encoded_length]u8 = undefined;
                out[0] = 0x00 + @as(u8, logn_);
                Codec.modqEncode(out[1..], &pk.h);
                return out;
            }

            /// Verify a compressed-format signature over `msg`.
            /// `sig_field` is the signature field as found on the wire:
            /// the `sig_header` byte followed by the compressed s2
            /// (exactly — no trailing bytes). The 40-byte nonce travels
            /// separately.
            pub fn verify(
                pk: *const @This(),
                msg: []const u8,
                nonce: *const [nonce_length]u8,
                sig_field: []const u8,
            ) VerifyError!void {
                if (sig_field.len < 2 or sig_field[0] != Self.sig_header) return error.InvalidSignature;
                var s2: [n]i16 = undefined;
                Codec.compDecode(&s2, sig_field[1..]) catch return error.InvalidSignature;

                var c: Ring.Poly = undefined;
                Codec.hashToPoint(nonce, msg, &c);

                // -s1 = s2*h - c mod q, normalized to [-q/2, q/2].
                var tt: Ring.Poly = undefined;
                for (&tt, s2) |*x, v| {
                    const w: i32 = v;
                    x.* = @intCast(if (w < 0) w + @as(i32, poly.q) else w);
                }
                Ring.ntt(&tt);
                Ring.pointwiseMul(&tt, &pk.h_ntt);
                Ring.intt(&tt);

                var norm: u64 = 0;
                for (tt, c, s2) |hs2, cc, v| {
                    var w: i64 = @as(i32, hs2) - @as(i32, cc);
                    w = @mod(w, poly.q);
                    if (w > poly.q / 2) w -= poly.q; // normalize -s1 coefficient
                    norm += @intCast(w * w);
                    norm += @intCast(@as(i64, v) * @as(i64, v));
                }
                if (norm > Self.sig_bound) return error.SignatureVerificationFailed;
            }
        };

        /// A decoded Falcon secret key basis (f, g, F; G is not stored in
        /// the encoding and is not needed for anything this module
        /// implements). f/g are trimmed to `fg_bits` bits (6 at n = 512,
        /// 5 at n = 1024 — the spec's per-degree secret-key encoding
        /// width); F is always 8 bits.
        pub const SecretKey = struct {
            f: [n]i8,
            g: [n]i8,
            big_f: [n]i8,

            const fg_bits: u4 = if (logn_ <= 9) 6 else 5;
            const big_f_bits: u4 = 8;
            const fg_len = n * fg_bits / 8;
            const big_f_len = n * big_f_bits / 8;

            pub const encoded_length = 1 + 2 * fg_len + big_f_len;

            /// Decode from the standard encoding: 0x50+logn header +
            /// trimmed f + trimmed g + trimmed F.
            pub fn fromBytes(bytes: *const [encoded_length]u8) error{InvalidSecretKey}!@This() {
                if (bytes[0] != 0x50 + @as(u8, logn_)) return error.InvalidSecretKey;
                var sk: @This() = undefined;
                Codec.trimI8Decode(&sk.f, fg_bits, bytes[1 .. 1 + fg_len]) catch return error.InvalidSecretKey;
                Codec.trimI8Decode(&sk.g, fg_bits, bytes[1 + fg_len .. 1 + 2 * fg_len]) catch return error.InvalidSecretKey;
                Codec.trimI8Decode(&sk.big_f, big_f_bits, bytes[1 + 2 * fg_len ..]) catch return error.InvalidSecretKey;
                return sk;
            }

            /// Recompute the public key h = g * f^-1 mod q.
            pub fn publicKey(sk: *const @This()) error{InvalidSecretKey}!Self.PublicKey {
                const h = Ring.computePublic(&sk.f, &sk.g) catch return error.InvalidSecretKey;
                var pk = Self.PublicKey{ .h = h, .h_ntt = h };
                Ring.ntt(&pk.h_ntt);
                return pk;
            }
        };

        /// Verify and open a NIST-API signed message (the KAT `sm`
        /// layout: 2-byte big-endian signature-field length || 40-byte
        /// nonce || message || signature field). Returns the message
        /// sub-slice of `sm` on success.
        pub fn openNistSignedMessage(pk: *const Self.PublicKey, sm: []const u8) VerifyError![]const u8 {
            if (sm.len < 2 + nonce_length + 1) return error.InvalidSignature;
            const sig_len = (@as(usize, sm[0]) << 8) | sm[1];
            if (sig_len < 1 or sig_len > sm.len - 2 - nonce_length) return error.InvalidSignature;
            const nonce = sm[2 .. 2 + nonce_length];
            const msg = sm[2 + nonce_length .. sm.len - sig_len];
            const sig_field = sm[sm.len - sig_len ..];
            try pk.verify(msg, nonce[0..nonce_length], sig_field);
            return msg;
        }

        // ---- Keygen + sign: scaffold, delegates the hard math to ntru/
        // ffsampling/gaussian (STUBS) — see module doc comment. ----

        const Keygen = keygen.Keygen(Ring);
        const Signer = sign.Signer(Ring);

        /// A generated Falcon signing key: the NTRU basis plus its
        /// precomputed ffSampling tree. See `keygen.zig`.
        pub const SigningKey = Self.Keygen.SigningKey;

        pub const KeygenError = error{NotInvertible};

        /// Generate a fresh Falcon key pair. `rng` is the entropy
        /// source (`std.crypto.random` for production, `sign.ShakePrng`
        /// seeded from a KAT `seed` for deterministic generation).
        /// STUB, transitively: panics inside `ntru.Ntru(Ring).generate`.
        pub fn generateKeyPair(rng: std.Random) Self.KeygenError!struct {
            signing_key: Self.SigningKey,
            public_key: Self.PublicKey,
        } {
            const kp = try Self.Keygen.generate(rng);
            var pk = Self.PublicKey{ .h = kp.public_key_h, .h_ntt = kp.public_key_h };
            Ring.ntt(&pk.h_ntt);
            return .{ .signing_key = kp.signing_key, .public_key = pk };
        }

        /// Randomized signing (production entry point): draws the nonce
        /// and every internal sampling decision from `rng`, a real
        /// CSPRNG. Writes the nonce to `nonce_out` and the compressed
        /// signature field to `sig_out` (see `sign.Signer.signWithRng`
        /// for the exact contract). STUB, transitively: panics inside
        /// `ffsampling.sampleSignature`.
        pub fn signRandomized(
            sk: *const Self.SigningKey,
            msg: []const u8,
            rng: std.Random,
            nonce_out: *[nonce_length]u8,
            sig_out: []u8,
        ) Self.Signer.SignError!usize {
            return Self.Signer.signWithRng(&sk.tree, msg, rng, nonce_out, sig_out, Self.sig_bound);
        }

        /// Deterministic signing (KAT reproduction): seeds
        /// `sign.ShakePrng` from `seed` (the NIST KAT .rsp `seed` field,
        /// once byte-exact reproduction is possible — see
        /// `sign.ShakePrng`'s doc comment for the caveats) instead of a
        /// real CSPRNG. STUB, transitively: panics inside
        /// `ffsampling.sampleSignature`.
        pub fn signDeterministic(
            sk: *const Self.SigningKey,
            msg: []const u8,
            seed: []const u8,
            nonce_out: *[nonce_length]u8,
            sig_out: []u8,
        ) Self.Signer.SignError!usize {
            var prng = sign.ShakePrng.init(seed);
            return Self.Signer.signWithRng(&sk.tree, msg, prng.random(), nonce_out, sig_out, Self.sig_bound);
        }
    };
}

/// Falcon-512 (n = 512, logn = 9); floor(beta^2) = 34034726 per the
/// Falcon Round-3 spec's Table 3.3 (verified against the reference
/// implementation's `common.c` l2bound[9]).
const P512 = Params(9, 34034726);

/// Falcon-1024 (n = 1024, logn = 10); floor(beta^2) = 70265242 — sourced
/// from the Falcon Round-3 reference implementation's `common.c`
/// `l2bound` table (falcon-sign.info/impl/common.c.html), entry index 10
/// (index = logn, 0 unused): `{0, 101498, 208714, 428865, 892039,
/// 1852696, 3842630, 7959734, 16468416, 34034726, 70265242}` — index 9
/// (34034726) is Falcon-512's bound above, confirming the table and its
/// indexing.
const P1024 = Params(10, 70265242);

// ---- Falcon-512: flat names, kept byte-for-byte backward compatible. ----

/// Header byte of a compressed Falcon-512 signature: 0x20 + logn.
pub const sig_header: u8 = P512.sig_header;

/// floor(beta^2) for Falcon-512 — inclusive bound on |(s1, s2)|^2.
pub const sig_bound: u64 = P512.sig_bound;

/// Maximum encoded signature field length (header + compressed s2) in the
/// NIST envelope: CRYPTO_BYTES - 2 - nonce = 690 - 42.
pub const max_sig_field_length = 648;

pub const PublicKey = P512.PublicKey;
pub const SecretKey = P512.SecretKey;
pub const openNistSignedMessage = P512.openNistSignedMessage;

/// A generated Falcon-512 signing key. STUB scaffold — see module doc.
pub const SigningKey = P512.SigningKey;
pub const KeygenError = P512.KeygenError;
pub const generateKeyPair = P512.generateKeyPair;
pub const signRandomized = P512.signRandomized;
pub const signDeterministic = P512.signDeterministic;

// ---- Falcon-1024: same shape, `_1024`-suffixed. ----

/// Header byte of a compressed Falcon-1024 signature: 0x20 + logn = 0x2a.
pub const sig_header_1024: u8 = P1024.sig_header;

/// floor(beta^2) for Falcon-1024 — inclusive bound on |(s1, s2)|^2.
pub const sig_bound_1024: u64 = P1024.sig_bound;

/// Maximum encoded signature field length (header + compressed s2) in the
/// NIST envelope: CRYPTO_BYTES - 2 - nonce = 1330 - 42 (the Falcon-1024
/// reference implementation's `api.h` CRYPTO_BYTES, from the same
/// official NIST Round-3 submission package as Falcon-512's 690).
pub const max_sig_field_length_1024 = 1288;

pub const PublicKey1024 = P1024.PublicKey;
pub const SecretKey1024 = P1024.SecretKey;
pub const openNistSignedMessage1024 = P1024.openNistSignedMessage;

test "public API surface: sizes, headers, bound" {
    try std.testing.expectEqual(@as(usize, 897), PublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 1281), SecretKey.encoded_length);
    try std.testing.expectEqual(@as(u8, 0x29), sig_header);
    try std.testing.expectEqual(@as(usize, 40), nonce_length);
    try std.testing.expectEqual(@as(u64, 34034726), sig_bound);
    try std.testing.expectEqual(@as(u32, 12289), poly.q);
    try std.testing.expectEqual(@as(usize, 512), poly.n);
}

test "public API surface (Falcon-1024): sizes, headers, bound" {
    try std.testing.expectEqual(@as(usize, 1793), PublicKey1024.encoded_length);
    try std.testing.expectEqual(@as(usize, 2305), SecretKey1024.encoded_length);
    try std.testing.expectEqual(@as(u8, 0x2a), sig_header_1024);
    try std.testing.expectEqual(@as(u64, 70265242), sig_bound_1024);
    try std.testing.expectEqual(@as(u32, 12289), poly.q);
    try std.testing.expectEqual(@as(usize, 1024), poly.Ring1024.n);
}

test {
    _ = poly;
    _ = codec;
    _ = fft;
    _ = gaussian;
    _ = ntru;
    _ = ffsampling;
    _ = keygen;
    _ = sign;
    _ = @import("fpr.zig");
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("keygen_sign_test.zig");
    _ = @import("kat_sign_test.zig");
}
