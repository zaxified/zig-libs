// SPDX-License-Identifier: MIT
//! falcon — Falcon-512 (FN-DSA, the NIST PQ lattice signature; NTRU +
//! fast-Fourier trapdoor sampling), pure Zig over std.crypto's SHAKE256.
//!
//! **Implemented (and NIST-Round-3-KAT-verified byte-exactly): signature
//! VERIFICATION and all key/signature codecs.** That is: public-key decode
//! (14-bit packed h), secret-key decode (trimmed f/g/F) plus the
//! h = g*f^-1 mod q consistency recomputation, compressed-signature
//! decode/re-encode (canonical Golomb-Rice), SHAKE256 hash-to-point,
//! negacyclic NTT over Z_q[x]/(x^512+1) with q = 12289, and the
//! s1 = c - s2*h short-vector norm check (floor(beta^2) = 34034726).
//! The KAT oracle is the official NIST Round-3 submission package's
//! `falcon512-KAT.rsp` (FIPS 206 / FN-DSA is still a draft; Round-3
//! Falcon is the stable interop target) — see src/kat_vectors.zig.
//!
//! **NOT implemented: key generation and signing.** Keygen needs the
//! NTRUSolve tower-of-fields big-integer machinery and signing needs the
//! ffSampling trapdoor Gaussian sampler (LDL* tree over the FFT
//! embedding); a subtly wrong sampler still yields signatures that
//! *verify* while silently leaking the private key, so it is out of scope
//! until it can be delivered KAT-exact. Also out of scope: Falcon-1024,
//! constant-time hardening (verification is public-data only, so this
//! matters only for a future signer), and the padded/CT signature
//! formats (the compressed format, which the KATs use, is implemented).
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

/// Ring/modulus parameters and the NTT (q = 12289, n = 512).
pub const poly = @import("poly.zig");

/// Wire encodings (modq / trimmed-i8 / compressed) + hash-to-point.
pub const codec = @import("codec.zig");

/// Nonce ("salt") length in every Falcon signature.
pub const nonce_length = 40;

/// Header byte of a compressed Falcon-512 signature: 0x20 + logn.
pub const sig_header: u8 = 0x20 + 9;

/// Maximum encoded signature field length (header + compressed s2) in the
/// NIST envelope: CRYPTO_BYTES - 2 - nonce = 690 - 42.
pub const max_sig_field_length = 648;

/// floor(beta^2) for Falcon-512 — inclusive bound on |(s1, s2)|^2.
pub const sig_bound: u64 = 34034726;

pub const VerifyError = error{
    /// Malformed signature: bad header, non-canonical compression,
    /// wrong length, or an sm envelope that does not parse.
    InvalidSignature,
    /// Well-formed signature that fails the lattice norm check.
    SignatureVerificationFailed,
};

/// A decoded Falcon-512 public key (h and its cached NTT form).
pub const PublicKey = struct {
    /// h in plain coefficient representation, coefficients in [0, q).
    h: poly.Poly,
    /// NTT(h), cached for verification.
    h_ntt: poly.Poly,

    pub const encoded_length = 897;

    /// Decode from the standard 897-byte encoding: 0x09 header + 14-bit
    /// packed coefficients.
    pub fn fromBytes(bytes: *const [encoded_length]u8) error{InvalidPublicKey}!PublicKey {
        if (bytes[0] != 0x00 + 9) return error.InvalidPublicKey;
        var pk: PublicKey = undefined;
        codec.modqDecode(&pk.h, bytes[1..]) catch return error.InvalidPublicKey;
        pk.h_ntt = pk.h;
        poly.ntt(&pk.h_ntt);
        return pk;
    }

    /// Re-encode to the standard 897-byte form.
    pub fn toBytes(pk: *const PublicKey) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0] = 0x00 + 9;
        codec.modqEncode(out[1..], &pk.h);
        return out;
    }

    /// Verify a compressed-format Falcon-512 signature over `msg`.
    /// `sig_field` is the signature field as found on the wire: the
    /// 0x29 header byte followed by the compressed s2 (exactly — no
    /// trailing bytes). The 40-byte nonce travels separately.
    pub fn verify(
        pk: *const PublicKey,
        msg: []const u8,
        nonce: *const [nonce_length]u8,
        sig_field: []const u8,
    ) VerifyError!void {
        if (sig_field.len < 2 or sig_field[0] != sig_header) return error.InvalidSignature;
        var s2: [poly.n]i16 = undefined;
        codec.compDecode(&s2, sig_field[1..]) catch return error.InvalidSignature;

        var c: poly.Poly = undefined;
        codec.hashToPoint(nonce, msg, &c);

        // -s1 = s2*h - c mod q, normalized to [-q/2, q/2].
        var tt: poly.Poly = undefined;
        for (&tt, s2) |*x, v| {
            const w: i32 = v;
            x.* = @intCast(if (w < 0) w + @as(i32, poly.q) else w);
        }
        poly.ntt(&tt);
        poly.pointwiseMul(&tt, &pk.h_ntt);
        poly.intt(&tt);

        var norm: u64 = 0;
        for (tt, c, s2) |hs2, cc, v| {
            var w: i64 = @as(i32, hs2) - @as(i32, cc);
            w = @mod(w, poly.q);
            if (w > poly.q / 2) w -= poly.q; // normalize -s1 coefficient
            norm += @intCast(w * w);
            norm += @intCast(@as(i64, v) * @as(i64, v));
        }
        if (norm > sig_bound) return error.SignatureVerificationFailed;
    }
};

/// A decoded Falcon-512 secret key basis (f, g, F; G is not stored in the
/// encoding and is not needed for anything this module implements).
pub const SecretKey = struct {
    f: [poly.n]i8,
    g: [poly.n]i8,
    big_f: [poly.n]i8,

    pub const encoded_length = 1281;

    /// Decode from the standard 1281-byte encoding: 0x59 header +
    /// 6-bit-trimmed f (384 B) + 6-bit-trimmed g (384 B) + 8-bit F (512 B).
    pub fn fromBytes(bytes: *const [encoded_length]u8) error{InvalidSecretKey}!SecretKey {
        if (bytes[0] != 0x50 + 9) return error.InvalidSecretKey;
        var sk: SecretKey = undefined;
        codec.trimI8Decode(&sk.f, 6, bytes[1..385]) catch return error.InvalidSecretKey;
        codec.trimI8Decode(&sk.g, 6, bytes[385..769]) catch return error.InvalidSecretKey;
        codec.trimI8Decode(&sk.big_f, 8, bytes[769..1281]) catch return error.InvalidSecretKey;
        return sk;
    }

    /// Recompute the public key h = g * f^-1 mod q.
    pub fn publicKey(sk: *const SecretKey) error{InvalidSecretKey}!PublicKey {
        const h = poly.computePublic(&sk.f, &sk.g) catch return error.InvalidSecretKey;
        var pk = PublicKey{ .h = h, .h_ntt = h };
        poly.ntt(&pk.h_ntt);
        return pk;
    }
};

/// Verify and open a NIST-API signed message (the KAT `sm` layout:
/// 2-byte big-endian signature-field length || 40-byte nonce || message
/// || signature field). Returns the message sub-slice of `sm` on success.
pub fn openNistSignedMessage(pk: *const PublicKey, sm: []const u8) VerifyError![]const u8 {
    if (sm.len < 2 + nonce_length + 1) return error.InvalidSignature;
    const sig_len = (@as(usize, sm[0]) << 8) | sm[1];
    if (sig_len < 1 or sig_len > sm.len - 2 - nonce_length) return error.InvalidSignature;
    const nonce = sm[2 .. 2 + nonce_length];
    const msg = sm[2 + nonce_length .. sm.len - sig_len];
    const sig_field = sm[sm.len - sig_len ..];
    try pk.verify(msg, nonce[0..nonce_length], sig_field);
    return msg;
}

test "public API surface: sizes, headers, bound" {
    try std.testing.expectEqual(@as(usize, 897), PublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 1281), SecretKey.encoded_length);
    try std.testing.expectEqual(@as(u8, 0x29), sig_header);
    try std.testing.expectEqual(@as(usize, 40), nonce_length);
    try std.testing.expectEqual(@as(u64, 34034726), sig_bound);
    try std.testing.expectEqual(@as(u32, 12289), poly.q);
    try std.testing.expectEqual(@as(usize, 512), poly.n);
}

test {
    _ = poly;
    _ = codec;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}
