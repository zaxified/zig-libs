// SPDX-License-Identifier: MIT

//! tls13.certverify -- TLS/DTLS 1.3 CertificateVerify signature construction
//! (RFC 8446 §4.4.3), reused VERBATIM by DTLS 1.3 (RFC 9147 does not
//! redefine it -- only the record/handshake HEADERS differ between TLS and
//! DTLS, never this message's signature construction). Moved from `dtls`
//! on 2026-10-20 (earlier history under `modules/dtls/src/certverify.zig`);
//! `dtls` re-exports it as `dtls.certverify`.
//!
//! Self-contained: it takes a caller-supplied transcript hash and typed key
//! and produces/verifies a CertificateVerify signature. Choosing the scheme,
//! hashing the transcript and framing the message are the engine's job
//! (`dtls`'s `Connection.zig` today, `tlsserver` next).
//!
//! ## What is implemented here
//! - `SignatureScheme`: the RFC 8446 §4.2.3 code points this file supports.
//! - `buildSignedContent`: the exact RFC 8446 §4.4.3 byte construction
//!   (64x0x20 || context_string || 0x00 || transcript_hash) -- deterministic
//!   byte-plumbing, unit-tested byte-exact below.
//! - The public `sign`/`verify` API surface: key-family dispatch, transcript
//!   hash length validation against the scheme's mandated hash, output
//!   buffer sizing, and error sets.
//! - The per-scheme sign/verify primitive calls themselves (`rsa.signPss`/
//!   `rsa.verifyPss`, std ECDSA sign/verify + ASN.1 DER encode/decode,
//!   Ed25519 sign/verify) -- the eight `signXxx`/`verifyXxx` private
//!   functions below. All are real, and validated by the byte-exact KATs in
//!   `certverify_kat_vectors.zig` (Ed25519 + RSA-PSS externally cross-checked
//!   against Python `cryptography`/OpenSSL; ECDSA reproduced byte-exact from
//!   std's deterministic sign path) plus sign/verify round-trip and tamper
//!   tests.

const std = @import("std");
const rsa = @import("rsa");
const p256 = @import("p256");
const p384 = @import("p384");
const p521 = @import("p521");
const ct25519 = @import("ct25519");
const burn = @import("burn.zig");

const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP521 = p521.EcdsaP521Sha512;
const mldsa = std.crypto.sign.mldsa;

// ── SignatureScheme (RFC 8446 §4.2.3) ────────────────────────────────────

/// TLS 1.3 `SignatureScheme` code points this module supports. RFC 8446
/// defines many more (legacy PKCS#1 v1.5 schemes for backward-compat-only
/// certificate verification, ecdsa_sha1, various historical/reserved
/// values); this module targets `rsa_pss_rsae_sha{256,384,512}`,
/// `ecdsa_secp{256,384,521}r1_sha*`, `ed25519` and pure ML-DSA
/// (`mldsa{44,65,87}`, draft-ietf-tls-mldsa, empty context; 2026-10-21 for
/// rustls parity) -- notably NOT `ed448` (a separate `ed448` module already
/// exists in this collection, see its README/SPEC) or the `rsa_pss_pss_*`
/// family (RSA-PSS with an embedded-in-the-key hash/salt-length identifier,
/// distinct from `rsa_pss_rsae_*`'s "any RSA key" form).
///
/// Non-exhaustive (`_`): callers may need to round-trip an unrecognized wire
/// value (e.g. to echo it back in a supported_algorithms rejection) without
/// this enum rejecting the parse outright; `sign`/`verify` reject unknown
/// values with `error.UnsupportedScheme`.
pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    mldsa44 = 0x0904,
    mldsa65 = 0x0905,
    mldsa87 = 0x0906,
    _,

    /// Digest length (bytes) of the hash this scheme signs with, for the
    /// schemes that route the signed content through a named hash function
    /// (RSA-PSS: the MGF1/message hash per RFC 8017 §8.1; ECDSA: the hash
    /// fed to the signature primitive per SEC1). Returns `null` for
    /// `ed25519` (PureEdDSA, RFC 8032 -- it hashes the message internally
    /// with SHA-512 and has no separate "signature hash" parameter to
    /// validate the caller's transcript hash length against), for ML-DSA
    /// (it hashes the message itself with SHAKE256) and for any
    /// unrecognized scheme.
    ///
    /// Not a constraint on the transcript hash: RFC 8446 §4.4.3 signs the
    /// suite's Transcript-Hash, whatever its length, and applies this hash
    /// to the signed content.
    pub fn hashDigestLen(scheme: SignatureScheme) ?usize {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256 => 32,
            .ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha384 => 48,
            .ecdsa_secp521r1_sha512, .rsa_pss_rsae_sha512 => 64,
            .ed25519, .mldsa44, .mldsa65, .mldsa87 => null,
            _ => null,
        };
    }
};

// ── Side + the RFC 8446 §4.4.3 signed-content construction ──────────────

/// Which end of the handshake is producing the CertificateVerify -- selects
/// the context string (RFC 8446 §4.4.3).
pub const Side = enum { server, client };

pub const server_context_string = "TLS 1.3, server CertificateVerify";
pub const client_context_string = "TLS 1.3, client CertificateVerify";

fn contextString(side: Side) []const u8 {
    return switch (side) {
        .server => server_context_string,
        .client => client_context_string,
    };
}

/// The RFC 8446 §4.4.3 fixed prefix length: 64 octets of the ASCII space
/// character (0x20), chosen specifically "to spread out any oracle attack
/// with the actual message signed by other TLS versions".
pub const signed_content_prefix_len = 64;

/// Largest transcript hash digest length this module's `SignatureScheme`
/// set ever mandates (SHA-512, for `rsa_pss_rsae_sha512`) -- sizes
/// `max_signed_content_len` and the stack buffer `sign`/`verify` build the
/// signed content into. A caller-supplied transcript hash longer than this
/// is rejected (`error.TranscriptHashTooLong`) rather than silently
/// truncated -- it cannot correspond to any scheme this module supports
/// anyway (RFC 8446 §4.2.3 has no signature-hash wider than SHA-512).
pub const max_transcript_hash_len = 64;

// Explicit `usize` annotation matters here: `@max` on two comptime-known
// `.len` values infers the SMALLEST integer type that fits the resulting
// value (e.g. `u6` for 33) rather than `usize` -- left implicit, the later
// `signed_content_prefix_len + max_context_len + ...` addition would then
// try to add 64 into a `u6`-typed peer and fail to compile ("type 'u6'
// cannot represent integer value '64'").
const max_context_len: usize = @max(server_context_string.len, client_context_string.len);

/// Largest possible `buildSignedContent` output this module can produce;
/// sized for the widest context string and `max_transcript_hash_len`.
pub const max_signed_content_len = signed_content_prefix_len + max_context_len + 1 + max_transcript_hash_len;

pub const BuildContentError = error{
    /// `transcript_hash.len` exceeds `max_transcript_hash_len` -- too long
    /// for any `SignatureScheme` this module supports.
    TranscriptHashTooLong,
    /// `out` is shorter than the exact content length
    /// (`signed_content_prefix_len + contextString(side).len + 1 + transcript_hash.len`).
    BufferTooSmall,
};

/// Builds the RFC 8446 §4.4.3 CertificateVerify signed content:
///
///   64 * 0x20  ||  context_string  ||  0x00  ||  transcript_hash
///
/// where `context_string` is `server_context_string` or
/// `client_context_string` depending on `side`, and `transcript_hash` is the
/// caller-computed running handshake-transcript hash (this file never
/// computes it -- that is the handshake state machine's job). Writes into
/// `out` and returns the written
/// subslice (exactly `signed_content_prefix_len + context_string.len + 1 +
/// transcript_hash.len` bytes).
///
/// This is pure byte-plumbing with no cryptographic operation of its own --
/// fully implemented and unit-tested byte-exact below (see the "signed
/// content" tests), independent of the `sign`/`verify` crypto.
pub fn buildSignedContent(side: Side, transcript_hash: []const u8, out: []u8) BuildContentError![]u8 {
    if (transcript_hash.len > max_transcript_hash_len) return error.TranscriptHashTooLong;
    const context = contextString(side);
    const total = signed_content_prefix_len + context.len + 1 + transcript_hash.len;
    if (out.len < total) return error.BufferTooSmall;

    @memset(out[0..signed_content_prefix_len], 0x20);
    @memcpy(out[signed_content_prefix_len..][0..context.len], context);
    out[signed_content_prefix_len + context.len] = 0x00;
    @memcpy(out[signed_content_prefix_len + context.len + 1 ..][0..transcript_hash.len], transcript_hash);
    return out[0..total];
}

// ── Public/secret key unions ─────────────────────────────────────────────

/// A CertificateVerify-capable public key, tagged by key family. The active
/// field must match the `SignatureScheme` family passed to `verify`
/// (`.rsa` for all three `rsa_pss_rsae_sha*` schemes -- the hash is selected
/// by the scheme, the key is hash-agnostic; `.ecdsa_p256`/`.ecdsa_p384`/
/// `.ed25519` are each paired with exactly one scheme) -- a mismatch is
/// rejected with `error.KeyMismatch` rather than silently misinterpreting
/// key bytes under the wrong algorithm.
pub const PublicKey = union(enum) {
    rsa: rsa.PublicKey,
    ecdsa_p256: Ecdsa.EcdsaP256Sha256.PublicKey,
    ecdsa_p384: Ecdsa.EcdsaP384Sha384.PublicKey,
    ecdsa_p521: EcdsaP521.PublicKey,
    ed25519: Ed25519.PublicKey,
    /// The encoded key (FIPS 204 `pkEncode`, the certificate's
    /// subjectPublicKey), BORROWED: std's decoded `PublicKey` carries the
    /// expanded matrix A (up to 56 KiB), so it is decoded inside `verify`'s
    /// burn, never held. Its length must be the parameter set's.
    mldsa44: []const u8,
    mldsa65: []const u8,
    mldsa87: []const u8,
};

/// A CertificateVerify-capable secret (signing) key, tagged by key family --
/// see `PublicKey`'s doc comment for the family/scheme pairing rule.
///
/// Every variant BORROWS the key: the pointee must outlive every use of the
/// union. A key held by value would be copied with every pass of the union
/// (an `rsa.SecretKey` alone is 11.8 KiB) and each copy is a secret left on
/// the dead stack of the frame that received it.
pub const SecretKey = union(enum) {
    rsa: *const rsa.SecretKey,
    ecdsa_p256: *const Ecdsa.EcdsaP256Sha256.SecretKey,
    ecdsa_p384: *const Ecdsa.EcdsaP384Sha384.SecretKey,
    ecdsa_p521: *const EcdsaP521.SecretKey,
    ed25519: *const Ed25519.SecretKey,
    /// The same key, prepared once (`Ed25519Signer`): `.once_at_load` signs
    /// with one base multiplication. Signs and negotiates as `ed25519`.
    ed25519_prepared: *const Ed25519Signer,
    /// std's expanded keys (~10-100 KiB with the cached NTT forms).
    mldsa44: *const mldsa.MLDSA44.SecretKey,
    mldsa65: *const mldsa.MLDSA65.SecretKey,
    mldsa87: *const mldsa.MLDSA87.SecretKey,
};

/// When an `Ed25519Signer` verifies that the public key stored in the secret
/// key really is `[a]B` for the seed.
pub const Ed25519PkCheck = enum {
    /// Once, in `init` (the default): signing is ONE base multiplication.
    once_at_load,
    /// In every signature, as `sign(.ed25519, ...)` does: a second base
    /// multiplication per call, so a key whose public half was corrupted in
    /// memory after load (a fault, a bit flip) is still caught before it can
    /// leak the scalar through two signatures under two public keys.
    every_sign,
};

/// An Ed25519 key prepared for CertificateVerify signing: the SHA-512
/// expansion and the public-key consistency check (seed -> `[a]B` ==
/// the key's embedded public half) are done once, in `init`.
///
/// `certverify.sign(.ed25519, ...)` keeps its behaviour -- it re-derives and
/// compares the public key on EVERY signature (= `.every_sign`); this type
/// is the opt-in way to sign with one base multiplication. Holds secrets
/// (the clamped scalar and the nonce prefix): `deinit` wipes it.
pub const Ed25519Signer = struct {
    a: [32]u8,
    prefix: [32]u8,
    public_key: [32]u8,
    pk_check: Ed25519PkCheck,

    pub const InitError = error{KeyMismatch};

    /// `.once_at_load`. `error.KeyMismatch` if the embedded public half is not
    /// the seed's.
    pub fn init(sk: *const Ed25519.SecretKey) InitError!Ed25519Signer {
        return initWith(sk, .once_at_load);
    }

    pub fn initWith(sk: *const Ed25519.SecretKey, pk_check: Ed25519PkCheck) InitError!Ed25519Signer {
        var self: Ed25519Signer = undefined;
        self.pk_check = pk_check;
        self.public_key = sk.publicKeyBytes();
        const ok = burn.run(burn.ed25519_burn, bool, loadChecked, .{ sk, &self });
        if (!ok) {
            std.crypto.secureZero(u8, std.mem.asBytes(&self));
            return error.KeyMismatch;
        }
        return self;
    }

    fn loadChecked(sk: *const Ed25519.SecretKey, self: *Ed25519Signer) bool {
        expandSeed(sk, &self.a, &self.prefix);
        var derived = ct25519.mulBaseEncode(self.a);
        defer std.crypto.secureZero(u8, &derived);
        return std.crypto.timing_safe.eql([32]u8, derived, self.public_key);
    }

    pub fn deinit(self: *Ed25519Signer) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// `certverify.sign` for this key: RFC 8446 §4.4.3 content from
    /// `(side, transcript_hash)`, the raw 64-byte signature written to `out`.
    pub fn sign(self: *const Ed25519Signer, side: Side, transcript_hash: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
        var content_buf: [max_signed_content_len]u8 = undefined;
        const content = try buildSignedContent(side, transcript_hash, &content_buf);
        return self.signContent(content, random, out);
    }

    /// `certverify.signContent` for this key.
    pub fn signContent(self: *const Ed25519Signer, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
        if (out.len < Ed25519.Signature.encoded_length) return error.BufferTooSmall;
        return burn.run(burn.ed25519_burn, SignError![]u8, signPrepared, .{ self, content, random, out });
    }

    fn signPrepared(self: *const Ed25519Signer, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
        return signCore(&self.a, &self.prefix, &self.public_key, self.pk_check == .every_sign, content, random, out);
    }
};

// ── candidateSchemes: signature_algorithms negotiation support ──────────

/// The `SignatureScheme`(s) `secret_key`'s key FAMILY can actually produce a
/// signature under, most-preferred first — the fact a negotiator (see
/// `dtls`'s `Connection.zig` `selectSignatureScheme`) needs to intersect against a
/// peer's advertised `signature_algorithms` list. An RSA key is hash-agnostic
/// (RFC 8446 §4.2.3: the same key works under any `rsa_pss_rsae_sha*`
/// scheme, differing only in which hash the PSS padding uses), so it has
/// three candidates; ECDSA/Ed25519 keys are each tied to exactly one scheme
/// (the curve fixes the hash). Never empty — every `SecretKey` union case
/// maps to at least one scheme.
// secret-api-ok: `SecretKey` is a tagged union of pointers to the key; this reads only the tag, never the key bytes.
pub fn candidateSchemes(secret_key: SecretKey) []const SignatureScheme {
    return switch (secret_key) {
        .rsa => &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
        .ecdsa_p256 => &.{.ecdsa_secp256r1_sha256},
        .ecdsa_p384 => &.{.ecdsa_secp384r1_sha384},
        .ecdsa_p521 => &.{.ecdsa_secp521r1_sha512},
        .ed25519, .ed25519_prepared => &.{.ed25519},
        .mldsa44 => &.{.mldsa44},
        .mldsa65 => &.{.mldsa65},
        .mldsa87 => &.{.mldsa87},
    };
}

/// Whether `secret_key` can sign under `scheme`: its family's candidate,
/// and for RSA-PSS a modulus large enough for the encoding (RFC 8017
/// §9.1.1: emLen = ceil((modBits − 1) / 8) ≥ hLen + sLen + 2, with
/// sLen = hLen per RFC 8446 §4.2.3) — a 1024-bit key cannot do
/// `rsa_pss_rsae_sha512` (128 < 130). A negotiator offering only what this
/// accepts never reaches a `sign` that fails for the key's size.
// secret-api-ok: reads the union's tag and the RSA public modulus length, never secret bytes.
pub fn canSign(secret_key: SecretKey, scheme: SignatureScheme) bool {
    if (std.mem.indexOfScalar(SignatureScheme, candidateSchemes(secret_key), scheme) == null) return false;
    return switch (secret_key) {
        .rsa => |k| pssFits(k.n.bits(), scheme),
        else => true,
    };
}

fn pssFits(mod_bits: usize, scheme: SignatureScheme) bool {
    const h: usize = switch (scheme) {
        .rsa_pss_rsae_sha256 => 32,
        .rsa_pss_rsae_sha384 => 48,
        .rsa_pss_rsae_sha512 => 64,
        else => return false,
    };
    if (mod_bits == 0) return false;
    return (mod_bits - 1 + 7) / 8 >= 2 * h + 2;
}

test "canSign: RSA-PSS needs emLen >= 2 hLen + 2" {
    // 1024-bit: emLen 128 — SHA-256 (66) and SHA-384 (98) fit, SHA-512 (130) not.
    try std.testing.expect(pssFits(1024, .rsa_pss_rsae_sha256));
    try std.testing.expect(pssFits(1024, .rsa_pss_rsae_sha384));
    try std.testing.expect(!pssFits(1024, .rsa_pss_rsae_sha512));
    // The boundary: emLen = ceil((b-1)/8) reaches 130 at modBits 1034.
    try std.testing.expect(!pssFits(1033, .rsa_pss_rsae_sha512));
    try std.testing.expect(pssFits(1034, .rsa_pss_rsae_sha512));
    try std.testing.expect(pssFits(2048, .rsa_pss_rsae_sha512));
    try std.testing.expect(!pssFits(2048, .ecdsa_secp256r1_sha256));
}

// ── maxSignatureLen: caller-facing output-buffer sizing ──────────────────

/// Conservative upper bound (bytes) on a `sign()` output for `scheme`, for
/// callers sizing an `out` buffer ahead of a call whose secret key they
/// don't have handy yet. For the RSA-PSS schemes this is `rsa.max_modulus_len`
/// (this module's dependency's compile-time ceiling), NOT the exact
/// signature length of any particular key -- `sign()` itself checks the
/// exact required length (`ceil(secret_key.rsa.n.bits() / 8)`) once it has
/// the actual key and returns `error.BufferTooSmall` precisely, so passing a
/// buffer this large is always sufficient but may be larger than necessary
/// for a specific (non-4096-bit) RSA key.
pub fn maxSignatureLen(scheme: SignatureScheme) usize {
    return switch (scheme) {
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => rsa.max_modulus_len,
        .ecdsa_secp256r1_sha256 => Ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max,
        .ecdsa_secp384r1_sha384 => Ecdsa.EcdsaP384Sha384.Signature.der_encoded_length_max,
        .ecdsa_secp521r1_sha512 => EcdsaP521.Signature.der_encoded_length_max,
        .ed25519 => Ed25519.Signature.encoded_length,
        .mldsa44 => mldsa.MLDSA44.Signature.encoded_length,
        .mldsa65 => mldsa.MLDSA65.Signature.encoded_length,
        .mldsa87 => mldsa.MLDSA87.Signature.encoded_length,
        _ => 0,
    };
}

/// The longest signature any scheme here produces (ML-DSA-87's 4627
/// octets; RSA-PSS is bounded by `rsa.max_modulus_len`).
pub const max_signature_len = @max(rsa.max_modulus_len, mldsa.MLDSA87.Signature.encoded_length);
comptime {
    for (std.enums.values(SignatureScheme)) |s| std.debug.assert(maxSignatureLen(s) <= max_signature_len);
}

// ── verify ────────────────────────────────────────────────────────────────

pub const VerifyError = BuildContentError || error{
    /// `scheme` is not one of the named `SignatureScheme` values this
    /// module implements.
    UnsupportedScheme,
    /// `public_key`'s active union field does not match the key family
    /// `scheme` requires.
    KeyMismatch,
    /// The signature is malformed (e.g. bad ASN.1 DER for an ECDSA scheme,
    /// wrong length for RSA-PSS/Ed25519) or cryptographically invalid for
    /// `(scheme, public_key, side, transcript_hash)`.
    InvalidSignature,
};

/// Verifies a CertificateVerify `signature` over the RFC 8446 §4.4.3 signed
/// content built from `(side, transcript_hash)`, under `scheme` and
/// `public_key`.
///
/// Non-crypto validation (transcript hash length, key-family match, content
/// construction) is fully implemented, then the actual cryptographic
/// signature check dispatches to one of the private `verifyXxx` primitives (eight schemes)
/// (see the "crypto dispatch" section below). The dispatch logic itself
/// (which primitive gets called for which scheme) is additionally covered by
/// the `KeyMismatch`/`UnsupportedScheme` reject-path
/// tests below, which short-circuit before reaching the crypto layer.
pub fn verify(
    scheme: SignatureScheme,
    public_key: PublicKey,
    side: Side,
    transcript_hash: []const u8,
    signature: []const u8,
) VerifyError!void {
    var content_buf: [max_signed_content_len]u8 = undefined;
    const content = try buildSignedContent(side, transcript_hash, &content_buf);
    return verifyContent(scheme, public_key, content, signature);
}

/// `verify` over content the caller built: for a signature in TLS 1.3's
/// form with another context string, as a delegated credential's (RFC
/// 9345 §4: "TLS, server delegated credentials" over the certificate and
/// the credential).
pub fn verifyContent(
    scheme: SignatureScheme,
    public_key: PublicKey,
    content: []const u8,
    signature: []const u8,
) VerifyError!void {
    return switch (scheme) {
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => blk: {
            const pk = switch (public_key) {
                .rsa => |k| k,
                else => return error.KeyMismatch,
            };
            break :blk verifyRsaPss(scheme, pk, content, signature);
        },
        .ecdsa_secp256r1_sha256 => blk: {
            const pk = switch (public_key) {
                .ecdsa_p256 => |k| k,
                else => return error.KeyMismatch,
            };
            break :blk verifyEcdsaP256(pk, content, signature);
        },
        .ecdsa_secp384r1_sha384 => blk: {
            const pk = switch (public_key) {
                .ecdsa_p384 => |k| k,
                else => return error.KeyMismatch,
            };
            break :blk verifyEcdsaP384(pk, content, signature);
        },
        .ecdsa_secp521r1_sha512 => blk: {
            const pk = switch (public_key) {
                .ecdsa_p521 => |k| k,
                else => return error.KeyMismatch,
            };
            break :blk verifyEcdsaP521(pk, content, signature);
        },
        .ed25519 => blk: {
            const pk = switch (public_key) {
                .ed25519 => |k| k,
                else => return error.KeyMismatch,
            };
            break :blk verifyEd25519(pk, content, signature);
        },
        inline .mldsa44, .mldsa65, .mldsa87 => |s| blk: {
            if (std.meta.activeTag(public_key) != @field(std.meta.Tag(PublicKey), @tagName(s))) return error.KeyMismatch;
            const pk = @field(public_key, @tagName(s));
            break :blk burn.run(@field(burn.mldsa_verify_burn, @tagName(s)), VerifyError!void, verifyMlDsa, .{ MlDsaOf(s), pk, content, signature });
        },
        _ => error.UnsupportedScheme,
    };
}

// ── sign ──────────────────────────────────────────────────────────────────

pub const SignError = BuildContentError || error{
    UnsupportedScheme,
    KeyMismatch,
    /// RFC 8446 §4.2.3 fixes RSA-PSS's salt length to `Hash.digest_length`
    /// for every `rsa_pss_rsae_*` scheme -- unlike RFC 8017 (PKCS#1 v2.2),
    /// which allows a `salt_len = 0` deterministic mode, TLS 1.3 has no
    /// deterministic RSA-PSS option, so `random == null` is a caller error
    /// for these three schemes specifically (ECDSA/Ed25519 accept
    /// `random == null` for a deterministic signature).
    RandomRequired,
    /// `out` is shorter than the scheme's exact signature length.
    BufferTooSmall,
    /// The RSA-CRT private operation's Bellcore fault-check (`rsa` re-encrypts
    /// `m^e ≡ c` before releasing the signature, RFC-8017-adjacent hardening)
    /// detected a corrupted computation. The signature is NOT produced — a
    /// hardware fault or fault-injection attack was caught. Security event,
    /// never a benign size/config error.
    FaultDetected,
};

/// Produces a CertificateVerify signature over the RFC 8446 §4.4.3 signed
/// content built from `(side, transcript_hash)`, under `scheme` and
/// `secret_key`, writing into `out` and returning the written subslice.
///
/// `random`: source of signing randomness.
///   - RSA-PSS (`rsa_pss_rsae_*`): the PSS salt, always drawn fresh at
///     `Hash.digest_length` bytes per RFC 8446 §4.2.3 -- `random == null` is
///     rejected with `error.RandomRequired` (see `SignError.RandomRequired`).
///   - ECDSA (`ecdsa_secp*r1_sha*`): optional additional noise mixed into
///     the otherwise-deterministic nonce derivation (defense-in-depth
///     against fault attacks, std's own doc comment on `KeyPair.sign`);
///     `random == null` yields a fully deterministic signature.
///   - Ed25519: same shape as ECDSA -- `random == null` yields the
///     standard deterministic (RFC 8032) signature.
///
/// Non-crypto validation + output-buffer sizing is fully implemented, then
/// the actual signing operation dispatches to one of the private `signXxx`
/// primitives (eight schemes) (see the "crypto dispatch" section below).
// secret-api-ok: `SecretKey` is a tagged union of pointers to the key (the by-value copy holds pointers, not key bytes); the signers it dispatches to run under their own burns.
pub fn sign(
    scheme: SignatureScheme,
    secret_key: SecretKey,
    side: Side,
    transcript_hash: []const u8,
    random: ?std.Random,
    out: []u8,
) SignError![]u8 {
    var content_buf: [max_signed_content_len]u8 = undefined;
    const content = try buildSignedContent(side, transcript_hash, &content_buf);
    return signContent(scheme, secret_key, content, random, out);
}

/// `sign` over content already built (`buildSignedContent`'s output): what
/// a signer holding the key elsewhere gets from a TLS stack that offloads
/// the CertificateVerify (BoringSSL `SSL_PRIVATE_KEY_METHOD.sign`'s `in`,
/// s2n `s2n_async_pkey_op_get_input`). The content is not checked against
/// RFC 8446 §4.4.3's form: any octets are signed.
// secret-api-ok: as `sign` — the union holds pointers; the signers run under their own burns.
pub fn signContent(
    scheme: SignatureScheme,
    secret_key: SecretKey,
    content: []const u8,
    random: ?std.Random,
    out: []u8,
) SignError![]u8 {
    return switch (scheme) {
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => blk: {
            const sk = switch (secret_key) {
                .rsa => |k| k,
                else => return error.KeyMismatch,
            };
            const rnd = random orelse return error.RandomRequired;
            const modulus_len = (sk.n.bits() + 7) / 8;
            if (out.len < modulus_len) return error.BufferTooSmall;
            break :blk burn.run(burn.rsa_burn, SignError![]u8, signRsaPss, .{ scheme, sk, content, rnd, out });
        },
        .ecdsa_secp256r1_sha256 => blk: {
            const sk = switch (secret_key) {
                .ecdsa_p256 => |k| k,
                else => return error.KeyMismatch,
            };
            if (out.len < Ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max) return error.BufferTooSmall;
            break :blk burn.run(burn.ecdsa_burn, SignError![]u8, signEcdsaP256, .{ sk, content, random, out });
        },
        .ecdsa_secp384r1_sha384 => blk: {
            const sk = switch (secret_key) {
                .ecdsa_p384 => |k| k,
                else => return error.KeyMismatch,
            };
            if (out.len < Ecdsa.EcdsaP384Sha384.Signature.der_encoded_length_max) return error.BufferTooSmall;
            break :blk burn.run(burn.ecdsa_burn, SignError![]u8, signEcdsaP384, .{ sk, content, random, out });
        },
        .ed25519 => blk: {
            const sk = switch (secret_key) {
                .ed25519 => |k| k,
                .ed25519_prepared => |signer| return signer.signContent(content, random, out),
                else => return error.KeyMismatch,
            };
            if (out.len < Ed25519.Signature.encoded_length) return error.BufferTooSmall;
            break :blk burn.run(burn.ed25519_burn, SignError![]u8, signEd25519, .{ sk, content, random, out });
        },
        .ecdsa_secp521r1_sha512 => blk: {
            const sk = switch (secret_key) {
                .ecdsa_p521 => |k| k,
                else => return error.KeyMismatch,
            };
            if (out.len < EcdsaP521.Signature.der_encoded_length_max) return error.BufferTooSmall;
            break :blk burn.run(burn.ecdsa_burn, SignError![]u8, signEcdsaP521, .{ sk, content, random, out });
        },
        inline .mldsa44, .mldsa65, .mldsa87 => |s| blk: {
            const M = MlDsaOf(s);
            if (std.meta.activeTag(secret_key) != @field(std.meta.Tag(SecretKey), @tagName(s))) return error.KeyMismatch;
            const sk = @field(secret_key, @tagName(s));
            if (out.len < M.Signature.encoded_length) return error.BufferTooSmall;
            break :blk burn.run(@field(burn.mldsa_sign_burn, @tagName(s)), SignError![]u8, signMlDsa, .{ M, sk, content, random, out });
        },
        _ => error.UnsupportedScheme,
    };
}

// ── crypto dispatch ─────────────────────────────────────────────────────
//
// The eight functions below are the module's entire irreducible-crypto
// surface: each wraps exactly one primitive call (+ DER glue for ECDSA) into
// this module's `content`/`signature` byte-slice shape. None of them is
// reached from the reject-path tests above (`KeyMismatch`/
// `UnsupportedScheme` all short-circuit before
// dispatch); the KAT tests in this file's `test` block below DO exercise
// them, byte-exact.

fn verifyRsaPss(scheme: SignatureScheme, pk: rsa.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    const sha2 = std.crypto.hash.sha2;
    // RFC 8446 §4.2.3: salt_len == Hash.digest_length for every
    // rsa_pss_rsae_* scheme (rsa.verifyPss hashes `content` internally, per
    // RFC 8017 §9.1.2 step 2 -- it takes the full message, not a pre-hash).
    return switch (scheme) {
        .rsa_pss_rsae_sha256 => rsa.verifyPss(pk, sha2.Sha256, content, signature, sha2.Sha256.digest_length) catch error.InvalidSignature,
        .rsa_pss_rsae_sha384 => rsa.verifyPss(pk, sha2.Sha384, content, signature, sha2.Sha384.digest_length) catch error.InvalidSignature,
        .rsa_pss_rsae_sha512 => rsa.verifyPss(pk, sha2.Sha512, content, signature, sha2.Sha512.digest_length) catch error.InvalidSignature,
        // `verify` only routes the three rsa_pss_rsae_* schemes here; kept as
        // a recoverable error (not `unreachable`) out of defensive caution.
        else => error.UnsupportedScheme,
    };
}

fn signRsaPss(scheme: SignatureScheme, sk: *const rsa.SecretKey, content: []const u8, random: std.Random, out: []u8) SignError![]u8 {
    const sha2 = std.crypto.hash.sha2;
    // RFC 8446 §4.2.3: salt_len == Hash.digest_length, always randomized
    // (`random` non-null is enforced by `sign` before dispatching here).
    // rsa.signPss hashes `content` internally (RFC 8017 §9.1.1 step 2) and
    // draws the fresh salt from `random` itself.
    const result = switch (scheme) {
        .rsa_pss_rsae_sha256 => rsa.signPss(sk, sha2.Sha256, random, content, sha2.Sha256.digest_length, out),
        .rsa_pss_rsae_sha384 => rsa.signPss(sk, sha2.Sha384, random, content, sha2.Sha384.digest_length, out),
        .rsa_pss_rsae_sha512 => rsa.signPss(sk, sha2.Sha512, random, content, sha2.Sha512.digest_length, out),
        else => return error.UnsupportedScheme, // `sign` only routes rsa_pss_rsae_* here
    };
    return result catch |err| switch (err) {
        // `out` too short (pre-checked by `sign` against the exact modulus
        // length, but mapped anyway).
        error.BufferTooSmall => error.BufferTooSmall,
        // Modulus too small to hold hash + salt + 2 (RFC 8017 §9.1.1 step 3)
        // -- impossible for any TLS-realistic key size, and a size problem
        // either way, so it maps to the same size error.
        error.EncodedMessageTooShort => error.BufferTooSmall,
        // Bellcore fault-check tripped inside the RSA-CRT private op: the
        // signature is withheld. Propagate as a distinct security signal, not
        // a size error.
        error.FaultDetected => error.FaultDetected,
    };
}

// The ECDSA arms compute on the collection's curves (`p256`, `p384`:
// asm field, fixed-base comb for `k·G`, 2026-10-21) behind std's key types,
// which stay the public API: a key crosses over as its octets. `p256`'s
// signatures are byte-exact with std's; `p384`'s nonce is RFC 6979's with
// the noise as §3.6 additional data, where std mixes in a zero block.

/// `pk.toUncompressedSec1()` without std's per-call field inversion. std's
/// `affineCoordinates` runs `z.invert()` (~255 squarings, about as long as
/// the verify gap to OpenSSL measured 2026-10-31) even when `z == 1`, which
/// is what `fromSec1` always produces. The key is public, so branching on
/// `z` is fine; any other `z` takes std's path.
fn uncompressedSec1P256(pk: Ecdsa.EcdsaP256Sha256.PublicKey) [65]u8 {
    const P = std.crypto.ecc.P256;
    if (pk.p.z.equivalent(P.Fe.one) and !pk.p.x.isZero()) {
        var out: [65]u8 = undefined;
        out[0] = 4;
        out[1..33].* = pk.p.x.toBytes(.big);
        out[33..65].* = pk.p.y.toBytes(.big);
        return out;
    }
    return pk.toUncompressedSec1();
}

fn verifyEcdsaP256(pk: Ecdsa.EcdsaP256Sha256.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // RFC 8446 §4.3.2: ECDSA signatures are ASN.1 DER on the wire, never raw
    // r||s. fromDer's EncodingError (malformed DER) and verify's whole error
    // set (SignatureVerificationFailed/IdentityElement/NonCanonical) all
    // collapse into this module's single InvalidSignature.
    const Fast = p256.EcdsaP256Sha256;
    const key = Fast.PublicKey.fromSec1(&uncompressedSec1P256(pk)) catch return error.InvalidSignature;
    const sig = Fast.Signature.fromDer(signature) catch return error.InvalidSignature;
    sig.verify(content, key) catch return error.InvalidSignature;
}

fn signEcdsaP256(sk: *const Ecdsa.EcdsaP256Sha256.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    const Fast = p256.EcdsaP256Sha256;
    // The secret scalar alone (no `d·G` per signature); it only fails on a
    // degenerate secret key (outside [1, n − 1]) -- a key problem, mapped to
    // KeyMismatch.
    var noise_buf: [Fast.noise_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise_buf);
    const noise: ?*const [Fast.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk &noise_buf;
    } else null; // null => std's fully deterministic nonce derivation
    var sig: Fast.Signature = undefined;
    Fast.signWithSecretKey(&sig, &.{ .bytes = sk.bytes }, content, noise) catch return error.KeyMismatch;
    // RFC 8446 §4.3.2 mandates DER on the wire; `sign` pre-checked
    // out.len >= der_encoded_length_max.
    return sig.toDer(out[0..Fast.Signature.der_encoded_length_max]);
}

fn verifyEcdsaP384(pk: Ecdsa.EcdsaP384Sha384.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // Same shape as verifyEcdsaP256, over the P-384/SHA-384 instantiation.
    const Fast = p384.EcdsaP384Sha384;
    const key = Fast.PublicKey.fromSec1(&pk.toUncompressedSec1()) catch return error.InvalidSignature;
    const sig = Fast.Signature.fromDer(signature) catch return error.InvalidSignature;
    sig.verify(content, key) catch return error.InvalidSignature;
}

fn signEcdsaP384(sk: *const Ecdsa.EcdsaP384Sha384.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    // Same shape as signEcdsaP256, over the P-384/SHA-384 instantiation
    // (noise_length is 48 here -- the curve's scalar length, not the caller's
    // concern: it comes from the Scheme type). `signWithSecretKey` refuses a
    // scalar outside [1, n − 1].
    const Fast = p384.EcdsaP384Sha384;
    var noise_buf: [Fast.noise_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise_buf);
    const noise: ?*const [Fast.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk &noise_buf;
    } else null; // null => RFC 6979 deterministic
    var sig: Fast.Signature = undefined;
    Fast.signWithSecretKey(&sig, &.{ .bytes = sk.bytes }, content, noise) catch return error.KeyMismatch;
    return sig.toDer(out[0..Fast.Signature.der_encoded_length_max]);
}

fn verifyEcdsaP521(pk: EcdsaP521.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // Same shape as verifyEcdsaP256, on the collection's `p521` (std has no
    // P-521); its `fromDer` is strict DER.
    const sig = EcdsaP521.Signature.fromDer(signature) catch return error.InvalidSignature;
    sig.verify(content, pk) catch return error.InvalidSignature;
}

fn signEcdsaP521(sk: *const EcdsaP521.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    // RFC 6979 nonces with the noise as §3.6 additional data (`p521`'s
    // `sign`); `fromSecretKeyInto` refuses a scalar outside [1, n − 1].
    var key_pair: EcdsaP521.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));
    EcdsaP521.KeyPair.fromSecretKeyInto(&key_pair, sk) catch return error.KeyMismatch;
    var noise_buf: [EcdsaP521.noise_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise_buf);
    const noise: ?[EcdsaP521.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk noise_buf;
    } else null; // null => RFC 6979 deterministic
    const sig = key_pair.sign(content, noise) catch return error.KeyMismatch;
    return sig.toDer(out[0..EcdsaP521.Signature.der_encoded_length_max]);
}

/// The std instantiation for an ML-DSA scheme.
fn MlDsaOf(comptime s: SignatureScheme) type {
    return switch (s) {
        .mldsa44 => mldsa.MLDSA44,
        .mldsa65 => mldsa.MLDSA65,
        .mldsa87 => mldsa.MLDSA87,
        else => @compileError("not an ML-DSA scheme"),
    };
}

fn verifyMlDsa(comptime M: type, encoded_key: []const u8, content: []const u8, signature: []const u8) VerifyError!void {
    // draft-ietf-tls-mldsa §3: pure ML-DSA (FIPS 204 §5.2) over the signed
    // content with an empty context string, the raw signature on the wire.
    // Both lengths are fixed by the parameter set.
    if (encoded_key.len != M.PublicKey.encoded_length) return error.KeyMismatch;
    if (signature.len != M.Signature.encoded_length) return error.InvalidSignature;
    const pk = M.PublicKey.fromBytes(encoded_key[0..M.PublicKey.encoded_length].*) catch return error.KeyMismatch;
    const sig = M.Signature.fromBytes(signature[0..M.Signature.encoded_length].*) catch return error.InvalidSignature;
    sig.verify(content, pk) catch return error.InvalidSignature;
}

fn signMlDsa(comptime M: type, sk: *const M.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    // Hedged (FIPS 204 §3.4) with `random`'s 32 octets, deterministic
    // without. std's signer borrows the key; its rejection loop cannot fail.
    var noise_buf: [M.noise_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise_buf);
    const noise: ?[M.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk noise_buf;
    } else null;
    var signer = sk.signer(noise) catch return error.KeyMismatch;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&signer));
    signer.update(content);
    const sig = signer.finalize().toBytes();
    @memcpy(out[0..M.Signature.encoded_length], &sig);
    return out[0..M.Signature.encoded_length];
}

fn verifyEd25519(pk: Ed25519.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // Ed25519 is the one scheme RFC 8446 §4.3.2 does NOT DER-wrap: the wire
    // signature is the raw 64-byte R || S encoding. fromBytes is infallible
    // (fixed-size array in), so the length check is ours.
    if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
    // verifyStrict: the conservative, cofactor-checked variant -- rejects
    // non-canonical encodings and small-order/mixed-order points that plain
    // verify tolerates. Every honestly-generated RFC 8032 signature (incl.
    // this module's KAT, OpenSSL-produced) passes strict verification.
    // `ct25519.verifyEd25519Strict` is std's `verifyStrict` with the same
    // verdict and error for every input (differentially tested there), on the
    // 4x64 field with a wNAF double-scalar multiplication.
    ct25519.verifyEd25519Strict(signature[0..Ed25519.Signature.encoded_length].*, content, pk.bytes) catch return error.InvalidSignature;
}

fn signEd25519(sk: *const Ed25519.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    // RFC 8032 §5.1.6 over `ct25519.mulBaseEncode2` (fixed-base comb on the
    // 4x64 field). std's `KeyPair.generateDeterministic` + `sign` would do two
    // base multiplications with its own ladder (one for the public half, one
    // for R); this does the same two with the comb, sharing one field
    // inversion. Byte-identical output to std's signer (pinned by the KATs).
    var a: [32]u8 = undefined;
    var prefix: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &a);
    defer std.crypto.secureZero(u8, &prefix);
    expandSeed(sk, &a, &prefix);
    const public_key = sk.publicKeyBytes();
    return signCore(&a, &prefix, &public_key, true, content, random, out);
}

/// RFC 8032 §5.1.5: `a` = the clamped low half of SHA-512(seed), `prefix` =
/// the high half.
fn expandSeed(sk: *const Ed25519.SecretKey, a: *[32]u8, prefix: *[32]u8) void {
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const seed = sk.seed();
    var h: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(&seed, &h, .{});
    defer std.crypto.secureZero(u8, &h);
    a.* = h[0..32].*;
    prefix.* = h[32..64].*;
    std.crypto.ecc.Edwards25519.scalar.clamp(a);
}

/// RFC 8032 §5.1.6. `check_public_key`: re-derive `[a]B` and compare it with
/// `public_key` (one extra base multiplication) -- two signatures of one
/// message under two public keys give away the secret scalar. Without it
/// `public_key` is trusted to be `[a]B` (`Ed25519Signer` checked it at load).
fn signCore(a: *const [32]u8, prefix: *const [32]u8, public_key: *const [32]u8, check_public_key: bool, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const scalar = std.crypto.ecc.Edwards25519.scalar;

    var noise_buf: [Ed25519.noise_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise_buf);
    var nonce_hash = Sha512.init(.{});
    if (random) |rnd| { // null => the standard deterministic RFC 8032 signature
        rnd.bytes(&noise_buf);
        nonce_hash.update(&noise_buf);
    }
    nonce_hash.update(prefix);
    nonce_hash.update(content);
    var r64: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &r64);
    nonce_hash.final(&r64);
    var r = scalar.reduce64(r64);
    defer std.crypto.secureZero(u8, &r);

    var r_bytes: [32]u8 = undefined;
    if (check_public_key) {
        // Compared in every mode (not only under `runtime_safety` like std).
        // Both base multiplications share one field inversion.
        const enc = ct25519.mulBaseEncode2(a.*, r);
        if (!std.crypto.timing_safe.eql([32]u8, enc[0], public_key.*)) return error.KeyMismatch;
        r_bytes = enc[1];
    } else {
        r_bytes = ct25519.mulBaseEncode(r);
    }
    // [r]B = O (r = 0 mod L, 2^-252) encodes as y = 1, x = 0.
    var identity_encoding: [32]u8 = @splat(0);
    identity_encoding[0] = 1;
    if (std.mem.eql(u8, &r_bytes, &identity_encoding)) return error.KeyMismatch;

    var k_hash = Sha512.init(.{});
    k_hash.update(&r_bytes);
    k_hash.update(public_key);
    k_hash.update(content);
    var k64: [64]u8 = undefined;
    k_hash.final(&k64);
    const k = scalar.reduce64(k64);
    var s_bytes = scalar.mulAdd(k, a.*, r);
    defer std.crypto.secureZero(u8, &s_bytes);

    // Raw 64-byte R || S encoding on the wire (NOT DER); the caller
    // pre-checked out.len >= encoded_length.
    @memcpy(out[0..32], &r_bytes);
    @memcpy(out[32..64], &s_bytes);
    return out[0..Ed25519.Signature.encoded_length];
}

// ── tests ─────────────────────────────────────────────────────────────────

const testing = std.testing;
const kat = @import("certverify_kat_vectors.zig");

// -- buildSignedContent: real, complete, byte-exact (no crypto involved) --

test "buildSignedContent: server side matches the ecdsa_p256_server KAT content byte-exact" {
    var buf: [max_signed_content_len]u8 = undefined;
    const content = try buildSignedContent(.server, &kat.ecdsa_p256_server.transcript_hash, &buf);
    try testing.expectEqualSlices(u8, &kat.ecdsa_p256_server.content, content);
}

test "buildSignedContent: client side matches the ed25519_client KAT content byte-exact" {
    var buf: [max_signed_content_len]u8 = undefined;
    const content = try buildSignedContent(.client, &kat.ed25519_client.transcript_hash, &buf);
    try testing.expectEqualSlices(u8, &kat.ed25519_client.content, content);
}

test "buildSignedContent: exact shape -- 64 spaces, context string, single 0x00, then the hash" {
    var buf: [max_signed_content_len]u8 = undefined;
    const transcript_hash = @as([32]u8, @splat(0xAA));
    const content = try buildSignedContent(.server, &transcript_hash, &buf);

    try testing.expectEqual(@as(usize, 64 + server_context_string.len + 1 + 32), content.len);
    // First 64 bytes are exactly 0x20 (RFC 8446 §4.4.3's "64 * 0x20").
    for (content[0..64]) |b| try testing.expectEqual(@as(u8, 0x20), b);
    // Next bytes are the ASCII context string, verbatim.
    try testing.expectEqualStrings(server_context_string, content[64..][0..server_context_string.len]);
    // Then a single 0x00 separator.
    try testing.expectEqual(@as(u8, 0x00), content[64 + server_context_string.len]);
    // Then exactly the transcript hash, untouched.
    try testing.expectEqualSlices(u8, &transcript_hash, content[64 + server_context_string.len + 1 ..]);
}

test "buildSignedContent: server vs. client differ only in the context string" {
    var buf_server: [max_signed_content_len]u8 = undefined;
    var buf_client: [max_signed_content_len]u8 = undefined;
    const transcript_hash = @as([48]u8, @splat(0x99));
    const server = try buildSignedContent(.server, &transcript_hash, &buf_server);
    const client = try buildSignedContent(.client, &transcript_hash, &buf_client);

    // Shared 64-byte prefix.
    try testing.expectEqualSlices(u8, server[0..64], client[0..64]);
    // Shared trailing "CertificateVerify" + 0x00 + transcript hash (both
    // context strings share this suffix, differing only in "server"/"client").
    try testing.expect(!std.mem.eql(u8, server, client));
    try testing.expectEqual(server.len, client.len); // same-length context strings
}

test "buildSignedContent: exact RFC 8446 §4.4.3 context strings, byte-for-byte" {
    try testing.expectEqualStrings("TLS 1.3, server CertificateVerify", server_context_string);
    try testing.expectEqualStrings("TLS 1.3, client CertificateVerify", client_context_string);
}

test "buildSignedContent: rejects an oversized transcript hash and an undersized buffer" {
    var buf: [max_signed_content_len]u8 = undefined;
    const too_long = @as([max_transcript_hash_len + 1]u8, @splat(0));
    try testing.expectError(error.TranscriptHashTooLong, buildSignedContent(.server, &too_long, &buf));

    const transcript_hash = @as([32]u8, @splat(0));
    var small: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, buildSignedContent(.server, &transcript_hash, &small));
}

// -- maxSignatureLen: real, complete -- every KAT signature/DER encoding
// -- below must fit inside its scheme's maxSignatureLen, or a caller sizing
// -- an `out` buffer off this function alone would be under-sized.

test "maxSignatureLen: bounds every KAT vector's actual signature length" {
    try testing.expect(kat.rsa_pss_sha256_server.signature.len <= maxSignatureLen(.rsa_pss_rsae_sha256));
    try testing.expect(kat.ecdsa_p256_server.signature_der.len <= maxSignatureLen(.ecdsa_secp256r1_sha256));
    try testing.expect(kat.ecdsa_p384_server.signature_der.len <= maxSignatureLen(.ecdsa_secp384r1_sha384));
    try testing.expectEqual(kat.ed25519_client.signature.len, maxSignatureLen(.ed25519)); // Ed25519 sigs are fixed-length, so this one is exact, not just an upper bound.
}

// -- SignatureScheme.hashDigestLen: real, complete --

test "SignatureScheme.hashDigestLen matches RFC 8446 §4.2.3's hash pairing" {
    try testing.expectEqual(@as(?usize, 32), SignatureScheme.ecdsa_secp256r1_sha256.hashDigestLen());
    try testing.expectEqual(@as(?usize, 48), SignatureScheme.ecdsa_secp384r1_sha384.hashDigestLen());
    try testing.expectEqual(@as(?usize, 32), SignatureScheme.rsa_pss_rsae_sha256.hashDigestLen());
    try testing.expectEqual(@as(?usize, 48), SignatureScheme.rsa_pss_rsae_sha384.hashDigestLen());
    try testing.expectEqual(@as(?usize, 64), SignatureScheme.rsa_pss_rsae_sha512.hashDigestLen());
    try testing.expectEqual(@as(?usize, null), SignatureScheme.ed25519.hashDigestLen());
}

test "SignatureScheme: RFC 8446 §4.2.3 wire code points" {
    try testing.expectEqual(@as(u16, 0x0403), @backingInt(SignatureScheme.ecdsa_secp256r1_sha256));
    try testing.expectEqual(@as(u16, 0x0503), @backingInt(SignatureScheme.ecdsa_secp384r1_sha384));
    try testing.expectEqual(@as(u16, 0x0804), @backingInt(SignatureScheme.rsa_pss_rsae_sha256));
    try testing.expectEqual(@as(u16, 0x0805), @backingInt(SignatureScheme.rsa_pss_rsae_sha384));
    try testing.expectEqual(@as(u16, 0x0806), @backingInt(SignatureScheme.rsa_pss_rsae_sha512));
    try testing.expectEqual(@as(u16, 0x0807), @backingInt(SignatureScheme.ed25519));
}

// -- candidateSchemes: real, complete --

test "candidateSchemes: an RSA key offers all three rsa_pss_rsae_* schemes" {
    var sk: rsa.SecretKey = undefined;
    try kat.rsa_pss_sha256_server.secretKey(&sk);
    const schemes = candidateSchemes(.{ .rsa = &sk });
    try testing.expectEqual(@as(usize, 3), schemes.len);
    try testing.expectEqual(SignatureScheme.rsa_pss_rsae_sha256, schemes[0]);
    try testing.expectEqual(SignatureScheme.rsa_pss_rsae_sha384, schemes[1]);
    try testing.expectEqual(SignatureScheme.rsa_pss_rsae_sha512, schemes[2]);
}

test "candidateSchemes: ECDSA/Ed25519 keys each offer exactly their one paired scheme" {
    const p256_sk = try kat.ecdsa_p256_server.secretKey();
    try testing.expectEqualSlices(SignatureScheme, &.{.ecdsa_secp256r1_sha256}, candidateSchemes(.{ .ecdsa_p256 = &p256_sk }));
    const p384_sk = try kat.ecdsa_p384_server.secretKey();
    try testing.expectEqualSlices(SignatureScheme, &.{.ecdsa_secp384r1_sha384}, candidateSchemes(.{ .ecdsa_p384 = &p384_sk }));
    const ed_kp = try kat.ed25519_client.keyPair();
    try testing.expectEqualSlices(SignatureScheme, &.{.ed25519}, candidateSchemes(.{ .ed25519 = &ed_kp.secret_key }));
}

// -- verify/sign reject-path dispatch: real, complete, never touches the
// -- panicking stubs (proves the dispatch logic itself doesn't need the
// -- crypto layer to be exercised) --

test "verify: rejects a key-family mismatch before reaching the crypto stub" {
    const wrong_key = PublicKey{ .ed25519 = (try kat.ed25519_client.keyPair()).public_key };
    try testing.expectError(error.KeyMismatch, verify(.ecdsa_secp256r1_sha256, wrong_key, .server, &kat.ecdsa_p256_server.transcript_hash, &kat.ecdsa_p256_server.signature_der));
}

test "sign/verify: the transcript hash is the suite's, not the scheme's (P-256 under SHA-384)" {
    // RFC 8446 §4.4.3: the signed content carries Transcript-Hash, the
    // cipher suite's hash; the scheme's hash is applied to that content.
    // TLS_AES_256_GCM_SHA384 with an ecdsa_secp256r1_sha256 certificate (a
    // common pairing) signs a 48-octet transcript hash. Until 2026-10-20
    // this was refused as `HashLengthMismatch` (a DTLS-only assumption:
    // dtls has SHA-256 suites only).
    const sk = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(kat.ecdsa_p256_server.secret_key_bytes);
    const pk = PublicKey{ .ecdsa_p256 = try kat.ecdsa_p256_server.publicKey() };
    const th48: [48]u8 = @splat(0x5c);
    var out: [Ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = try sign(.ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = &sk }, .server, &th48, null, &out);
    try verify(.ecdsa_secp256r1_sha256, pk, .server, &th48, sig);
    // And RSA-PSS SHA-512 over a SHA-256 transcript.
    const rpk = PublicKey{ .rsa = try kat.rsa_pss_sha256_server.publicKey() };
    try testing.expectError(error.InvalidSignature, verify(.rsa_pss_rsae_sha512, rpk, .server, &kat.rsa_pss_sha256_server.transcript_hash, &kat.rsa_pss_sha256_server.signature));
    // The only length limit left is the content buffer's.
    const th65: [65]u8 = @splat(0);
    try testing.expectError(error.TranscriptHashTooLong, verify(.ecdsa_secp256r1_sha256, pk, .server, &th65, sig));
}

test "verify: rejects an unrecognized SignatureScheme wire value" {
    const pk = PublicKey{ .ed25519 = (try kat.ed25519_client.keyPair()).public_key };
    const unknown: SignatureScheme = @fromBackingInt(@intCast(0xffff));
    try testing.expectError(error.UnsupportedScheme, verify(unknown, pk, .client, &kat.ed25519_client.transcript_hash, &kat.ed25519_client.signature));
}

test "sign: rejects a key-family mismatch before reaching the crypto stub" {
    const ed_sk = try std.crypto.sign.Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes);
    const wrong_key = SecretKey{ .ed25519 = &ed_sk };
    var out: [max_signed_content_len]u8 = undefined;
    try testing.expectError(error.KeyMismatch, sign(.ecdsa_secp256r1_sha256, wrong_key, .server, &kat.ecdsa_p256_server.transcript_hash, null, &out));
}

test "sign: RSA-PSS schemes require a random source (RFC 8446 §4.2.3 forbids salt_len = 0)" {
    var rsa_sk: rsa.SecretKey = undefined;
    try kat.rsa_pss_sha256_server.secretKey(&rsa_sk);
    const sk = SecretKey{ .rsa = &rsa_sk };
    var out: [rsa.max_modulus_len]u8 = undefined;
    try testing.expectError(error.RandomRequired, sign(.rsa_pss_rsae_sha256, sk, .server, &kat.rsa_pss_sha256_server.transcript_hash, null, &out));
}

test "sign: rejects an undersized output buffer before reaching the crypto stub" {
    const ec_sk = try kat.ecdsa_p256_server.secretKey();
    const sk = SecretKey{ .ecdsa_p256 = &ec_sk };
    var too_small: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, sign(.ecdsa_secp256r1_sha256, sk, .server, &kat.ecdsa_p256_server.transcript_hash, null, &too_small));
}

// -- KATs exercising the crypto dispatch, byte-exact --
//
// These prove the *vectors* themselves are real (independently generated --
// see certverify_kat_vectors.zig's provenance comments) and that
// `verify`/`sign` reproduce/accept them byte-exact. A verify KAT is a real
// cryptographic check (it cannot pass for a tampered signature or a wrong
// key); a sign KAT reproduces a deterministic vector byte-for-byte (it fails
// on a single wrong byte). Each scheme additionally has a tamper test that
// asserts a bit-flip is rejected with `error.InvalidSignature`.

test "KAT: rsa_pss_rsae_sha256 verify accepts the OpenSSL-external vector" {
    const pk = PublicKey{ .rsa = try kat.rsa_pss_sha256_server.publicKey() };
    try verify(.rsa_pss_rsae_sha256, pk, .server, &kat.rsa_pss_sha256_server.transcript_hash, &kat.rsa_pss_sha256_server.signature);
}

test "KAT: rsa_pss_rsae_sha256 verify rejects a tampered signature" {
    const pk = PublicKey{ .rsa = try kat.rsa_pss_sha256_server.publicKey() };
    var tampered = kat.rsa_pss_sha256_server.signature;
    tampered[0] ^= 0x01;
    try testing.expectError(error.InvalidSignature, verify(.rsa_pss_rsae_sha256, pk, .server, &kat.rsa_pss_sha256_server.transcript_hash, &tampered));
}

test "KAT: rsa_pss_rsae_sha256 sign/verify round-trip with a fresh random salt" {
    var rsa_sk: rsa.SecretKey = undefined;
    try kat.rsa_pss_sha256_server.secretKey(&rsa_sk);
    const sk = SecretKey{ .rsa = &rsa_sk };
    const pk = PublicKey{ .rsa = try kat.rsa_pss_sha256_server.publicKey() };
    var prng = std.Random.DefaultPrng.init(0x63657274766572);
    var out: [rsa.max_modulus_len]u8 = undefined;
    const sig = try sign(.rsa_pss_rsae_sha256, sk, .server, &kat.rsa_pss_sha256_server.transcript_hash, prng.random(), &out);
    try verify(.rsa_pss_rsae_sha256, pk, .server, &kat.rsa_pss_sha256_server.transcript_hash, sig);
}

test "KAT: ecdsa_secp256r1_sha256 verify accepts the self-generated-deterministic DER vector" {
    const pk = PublicKey{ .ecdsa_p256 = try kat.ecdsa_p256_server.publicKey() };
    try verify(.ecdsa_secp256r1_sha256, pk, .server, &kat.ecdsa_p256_server.transcript_hash, &kat.ecdsa_p256_server.signature_der);
}

test "KAT: ecdsa_secp256r1_sha256 verify rejects a tampered signature" {
    const pk = PublicKey{ .ecdsa_p256 = try kat.ecdsa_p256_server.publicKey() };
    var tampered = kat.ecdsa_p256_server.signature_der;
    tampered[tampered.len - 1] ^= 0x01;
    try testing.expectError(error.InvalidSignature, verify(.ecdsa_secp256r1_sha256, pk, .server, &kat.ecdsa_p256_server.transcript_hash, &tampered));
}

test "KAT: ecdsa_secp256r1_sha256 sign reproduces the deterministic DER vector byte-exact" {
    const ec_sk = try kat.ecdsa_p256_server.secretKey();
    const sk = SecretKey{ .ecdsa_p256 = &ec_sk };
    var out: [Ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = try sign(.ecdsa_secp256r1_sha256, sk, .server, &kat.ecdsa_p256_server.transcript_hash, null, &out);
    try testing.expectEqualSlices(u8, &kat.ecdsa_p256_server.signature_der, sig);
}

test "KAT: ecdsa_secp384r1_sha384 verify accepts the OpenSSL RFC 6979 DER vector" {
    const pk = PublicKey{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() };
    try verify(.ecdsa_secp384r1_sha384, pk, .server, &kat.ecdsa_p384_server.transcript_hash, &kat.ecdsa_p384_server.signature_der);
}

test "KAT: ecdsa_secp384r1_sha384 sign reproduces OpenSSL's RFC 6979 DER vector byte-exact" {
    const ec_sk = try kat.ecdsa_p384_server.secretKey();
    const sk = SecretKey{ .ecdsa_p384 = &ec_sk };
    var out: [Ecdsa.EcdsaP384Sha384.Signature.der_encoded_length_max]u8 = undefined;
    const sig = try sign(.ecdsa_secp384r1_sha384, sk, .server, &kat.ecdsa_p384_server.transcript_hash, null, &out);
    try testing.expectEqualSlices(u8, &kat.ecdsa_p384_server.signature_der, sig);
}

test "KAT: ed25519 verify accepts the cryptography-cross-checked vector" {
    const pk = PublicKey{ .ed25519 = try Ed25519.PublicKey.fromBytes(kat.ed25519_client.public_key_bytes) };
    try verify(.ed25519, pk, .client, &kat.ed25519_client.transcript_hash, &kat.ed25519_client.signature);
}

test "KAT: ed25519 verify rejects a tampered signature" {
    const pk = PublicKey{ .ed25519 = try Ed25519.PublicKey.fromBytes(kat.ed25519_client.public_key_bytes) };
    var tampered = kat.ed25519_client.signature;
    tampered[0] ^= 0x01;
    try testing.expectError(error.InvalidSignature, verify(.ed25519, pk, .client, &kat.ed25519_client.transcript_hash, &tampered));
}

test "sign: an Ed25519 secret key whose embedded public half is not its own is KeyMismatch in every mode" {
    // `std`'s `KeyPair.fromSecretKey` makes this check only under runtime
    // safety; the ReleaseFast lane is the one that proves ours runs anyway.
    var bytes = kat.ed25519_client.secret_key_bytes;
    bytes[63] ^= 0x01; // flip a bit of the public half, keep the seed
    const ed_sk = try Ed25519.SecretKey.fromBytes(bytes);
    const sk = SecretKey{ .ed25519 = &ed_sk };
    var out: [Ed25519.Signature.encoded_length]u8 = undefined;
    try testing.expectError(error.KeyMismatch, sign(.ed25519, sk, .client, &kat.ed25519_client.transcript_hash, null, &out));
}

test "KAT: ed25519 sign reproduces the cryptography-cross-checked vector byte-exact" {
    const ed_sk = try Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes);
    const sk = SecretKey{ .ed25519 = &ed_sk };
    var out: [Ed25519.Signature.encoded_length]u8 = undefined;
    const sig = try sign(.ed25519, sk, .client, &kat.ed25519_client.transcript_hash, null, &out);
    try testing.expectEqualSlices(u8, &kat.ed25519_client.signature, sig);
}

test "KAT: signContent over buildSignedContent's output is sign's signature (Ed25519, ECDSA P-384)" {
    var content_buf: [max_signed_content_len]u8 = undefined;
    const ed_sk = try Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes);
    var out: [max_signature_len]u8 = undefined;
    const ed_content = try buildSignedContent(.client, &kat.ed25519_client.transcript_hash, &content_buf);
    try testing.expectEqualSlices(u8, &kat.ed25519_client.signature, try signContent(.ed25519, .{ .ed25519 = &ed_sk }, ed_content, null, &out));
    const ec_sk = try kat.ecdsa_p384_server.secretKey();
    const ec_content = try buildSignedContent(.server, &kat.ecdsa_p384_server.transcript_hash, &content_buf);
    try testing.expectEqualSlices(u8, &kat.ecdsa_p384_server.signature_der, try signContent(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = &ec_sk }, ec_content, null, &out));
}

test "KAT: verifyContent over buildSignedContent's output is verify (Ed25519); other content fails" {
    var content_buf: [max_signed_content_len]u8 = undefined;
    const pk = PublicKey{ .ed25519 = try Ed25519.PublicKey.fromBytes(kat.ed25519_client.public_key_bytes) };
    const content = try buildSignedContent(.client, &kat.ed25519_client.transcript_hash, &content_buf);
    try verifyContent(.ed25519, pk, content, &kat.ed25519_client.signature);
    content[0] ^= 1;
    try testing.expectError(error.InvalidSignature, verifyContent(.ed25519, pk, content, &kat.ed25519_client.signature));
}

test "KAT: ecdsa_secp521r1_sha512 sign reproduces OpenSSL's RFC 6979 DER vector byte-exact, verify accepts it" {
    const v = kat.ecdsa_p521_server;
    const sk = try EcdsaP521.SecretKey.fromBytes(v.secret_key_bytes);
    var out: [EcdsaP521.Signature.der_encoded_length_max]u8 = undefined;
    const sig = try sign(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk }, .server, &v.transcript_hash, null, &out);
    try testing.expectEqualSlices(u8, &v.signature_der, sig);
    const pk = PublicKey{ .ecdsa_p521 = try EcdsaP521.PublicKey.fromSec1(&v.public_key_uncompressed_sec1) };
    try verify(.ecdsa_secp521r1_sha512, pk, .server, &v.transcript_hash, &v.signature_der);
    var tampered = v.signature_der;
    tampered[tampered.len - 1] ^= 0x01;
    try testing.expectError(error.InvalidSignature, verify(.ecdsa_secp521r1_sha512, pk, .server, &v.transcript_hash, &tampered));
    // The other side's context string is another message.
    try testing.expectError(error.InvalidSignature, verify(.ecdsa_secp521r1_sha512, pk, .client, &v.transcript_hash, &v.signature_der));
    // A P-384 key under the P-521 scheme.
    try testing.expectError(error.KeyMismatch, verify(.ecdsa_secp521r1_sha512, .{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() }, .server, &v.transcript_hash, &v.signature_der));
}

fn expectMlDsaKat(comptime scheme: SignatureScheme, comptime v: kat.MlDsaVector) !void {
    const M = MlDsaOf(scheme);
    const kp = try testing.allocator.create(M.KeyPair);
    defer testing.allocator.destroy(kp);
    kp.* = try M.KeyPair.generateDeterministic(v.seed);
    const pk_bytes = kp.public_key.toBytes();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&pk_bytes, &digest, .{});
    try testing.expectEqualSlices(u8, &v.public_key_sha256, &digest);

    const sk: SecretKey = @unionInit(SecretKey, @tagName(scheme), &kp.secret_key);
    var out: [max_signature_len]u8 = undefined;
    const sig = try sign(scheme, sk, .server, &v.transcript_hash, null, &out);
    try testing.expectEqual(maxSignatureLen(scheme), sig.len);
    std.crypto.hash.sha2.Sha256.hash(sig, &digest, .{});
    try testing.expectEqualSlices(u8, &v.signature_sha256, &digest);

    const pk: PublicKey = @unionInit(PublicKey, @tagName(scheme), &pk_bytes);
    try verify(scheme, pk, .server, &v.transcript_hash, sig);
    // Hedged signatures differ and verify too.
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5a)));
    var hedged_buf: [max_signature_len]u8 = undefined;
    const hedged = try sign(scheme, sk, .server, &v.transcript_hash, csprng.random(), &hedged_buf);
    try testing.expect(!std.mem.eql(u8, sig, hedged));
    try verify(scheme, pk, .server, &v.transcript_hash, hedged);
    // Tampered, truncated, the other context, a key of the wrong length.
    out[17] ^= 0x01;
    try testing.expectError(error.InvalidSignature, verify(scheme, pk, .server, &v.transcript_hash, sig));
    out[17] ^= 0x01;
    try testing.expectError(error.InvalidSignature, verify(scheme, pk, .server, &v.transcript_hash, sig[0 .. sig.len - 1]));
    // One octet more: the length is the parameter set's, exactly.
    var longer: [max_signature_len + 1]u8 = undefined;
    @memcpy(longer[0..sig.len], sig);
    longer[sig.len] = 0;
    try testing.expectError(error.InvalidSignature, verify(scheme, pk, .server, &v.transcript_hash, longer[0 .. sig.len + 1]));
    try testing.expectError(error.InvalidSignature, verify(scheme, pk, .client, &v.transcript_hash, sig));
    try testing.expectError(error.KeyMismatch, verify(scheme, @unionInit(PublicKey, @tagName(scheme), pk_bytes[1..]), .server, &v.transcript_hash, sig));
    // A buffer one short.
    try testing.expectError(error.BufferTooSmall, sign(scheme, sk, .server, &v.transcript_hash, null, out[0 .. maxSignatureLen(scheme) - 1]));
}

test "KAT: mldsa44/65/87 keygen and deterministic sign hash to OpenSSL's, verify and reject" {
    try expectMlDsaKat(.mldsa44, kat.mldsa44_server);
    try expectMlDsaKat(.mldsa65, kat.mldsa65_server);
    try expectMlDsaKat(.mldsa87, kat.mldsa87_server);
}

test "ML-DSA: a key of another parameter set is KeyMismatch both ways" {
    const kp = try testing.allocator.create(mldsa.MLDSA44.KeyPair);
    defer testing.allocator.destroy(kp);
    kp.* = try mldsa.MLDSA44.KeyPair.generateDeterministic(@splat(1));
    var out: [max_signature_len]u8 = undefined;
    const th = @as([32]u8, @splat(0));
    try testing.expectError(error.KeyMismatch, sign(.mldsa65, .{ .mldsa44 = &kp.secret_key }, .server, &th, null, &out));
    const pk_bytes = kp.public_key.toBytes();
    try testing.expectError(error.KeyMismatch, verify(.mldsa65, .{ .mldsa44 = &pk_bytes }, .server, &th, out[0..3309]));
    try testing.expect(canSign(.{ .mldsa44 = &kp.secret_key }, .mldsa44));
    try testing.expect(!canSign(.{ .mldsa44 = &kp.secret_key }, .mldsa87));
}

test "verify: Ed25519 is cofactorless (verifyStrict) -- a signature whose R carries a torsion part is refused" {
    // R' = r·B + T with T the order-2 point (0, -1), S = r + H(R' || A || m)·a.
    // The cofactored equation [8][S]B = [8]R' + [8][k]A holds ([8]T is the
    // identity), so std's plain `verify` accepts it; the cofactorless
    // [S]B = R' + [k]A does not. RFC 8032 §5.1.7 leaves the choice open; this
    // module pins the strict one (see `verifyEd25519`).
    const Curve = std.crypto.ecc.Edwards25519;
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const seed: [32]u8 = @splat(0x42);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var expanded: [64]u8 = undefined;
    Sha512.hash(&seed, &expanded, .{});
    var a = expanded[0..32].*;
    Curve.scalar.clamp(&a);
    const r = Curve.scalar.reduce64(@as([64]u8, @splat(0x17)));
    var t_bytes: [32]u8 = @splat(0xff);
    t_bytes[0] = 0xec;
    t_bytes[31] = 0x7f;
    const t = try Curve.fromBytes(t_bytes);
    const r_point = (try Curve.basePoint.mul(r)).add(t);
    const r_bytes = r_point.toBytes();
    const content = "torsion in R";
    var h = Sha512.init(.{});
    h.update(&r_bytes);
    h.update(&kp.public_key.toBytes());
    h.update(content);
    var hram: [64]u8 = undefined;
    h.final(&hram);
    const s = Curve.scalar.mulAdd(Curve.scalar.reduce64(hram), a, r);
    const sig = r_bytes ++ s;
    // The vector is meaningful: the cofactored check accepts it.
    try Ed25519.Signature.fromBytes(sig).verify(content, kp.public_key);
    try testing.expectError(error.InvalidSignature, verifyContent(.ed25519, .{ .ed25519 = kp.public_key }, content, &sig));
}

test "KAT: Ed25519 signer reproduces RFC 8032 section 7.1 TESTs 1, 2, 3 and 1024 byte-exact" {
    const Case = struct { sk: []const u8, pk: []const u8, msg: []const u8, sig: []const u8 };
    const cases = [_]Case{
        .{
            .sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            .pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            .msg = "",
            .sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        .{
            .sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            .pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            .msg = "72",
            .sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        .{
            .sk = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            .pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            .msg = "af82",
            .sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
        .{
            .sk = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            .pk = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            .msg = "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            .sig = "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        },
    };
    for (cases) |c| {
        var sk_bytes: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(sk_bytes[0..32], c.sk);
        _ = try std.fmt.hexToBytes(sk_bytes[32..], c.pk);
        const sk = try Ed25519.SecretKey.fromBytes(sk_bytes);
        var msg_buf: [1023]u8 = undefined;
        const msg = try std.fmt.hexToBytes(&msg_buf, c.msg);
        var want: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, c.sig);
        var out: [64]u8 = undefined;
        const got = try signEd25519(&sk, msg, null, &out);
        try testing.expectEqualSlices(u8, &want, got);
    }
}

test "Ed25519 signer is byte-identical to std's (deterministic) over many seeds and lengths" {
    var prng = std.Random.DefaultPrng.init(0x8032);
    const rnd = prng.random();
    var msg: [300]u8 = undefined;
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        var seed: [32]u8 = undefined;
        rnd.bytes(&seed);
        rnd.bytes(&msg);
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        const len = (i * 7) % msg.len;
        const want = (try kp.sign(msg[0..len], null)).toBytes();
        var out: [64]u8 = undefined;
        const got = try signEd25519(&kp.secret_key, msg[0..len], null, &out);
        try testing.expectEqualSlices(u8, &want, got);
        // Noisy signatures differ per call but verify under the public key.
        const noisy = try signEd25519(&kp.secret_key, msg[0..len], rnd, &out);
        try Ed25519.Signature.fromBytes(noisy[0..64].*).verifyStrict(msg[0..len], kp.public_key);
    }
}

test "Ed25519 signer: a secret key whose public half does not match the seed is KeyMismatch" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    var out: [64]u8 = undefined;
    // Every byte of the embedded public half is compared (not a prefix).
    for (32..64) |i| {
        var bytes = kp.secret_key.toBytes();
        bytes[i] ^= 0x80;
        const bad = try Ed25519.SecretKey.fromBytes(bytes);
        try testing.expectError(error.KeyMismatch, signEd25519(&bad, "m", null, &out));
    }
}

test "Ed25519Signer: byte-identical to sign(.ed25519) in both modes, deterministic and hedged" {
    const kp = try kat.ed25519_client.keyPair();
    var want: [64]u8 = undefined;
    var got: [64]u8 = undefined;
    const content = "prepared signer content";
    for ([_]Ed25519PkCheck{ .once_at_load, .every_sign }) |mode| {
        var signer = try Ed25519Signer.initWith(&kp.secret_key, mode);
        defer signer.deinit();
        _ = try signContent(.ed25519, .{ .ed25519 = &kp.secret_key }, content, null, &want);
        _ = try signer.signContent(content, null, &got);
        try testing.expectEqualSlices(u8, &want, &got);
        var prng2 = std.Random.DefaultPrng.init(9);
        _ = try signContent(.ed25519, .{ .ed25519 = &kp.secret_key }, content, prng2.random(), &want);
        prng2 = std.Random.DefaultPrng.init(9);
        _ = try signer.signContent(content, prng2.random(), &got);
        try testing.expectEqualSlices(u8, &want, &got);
        // sign() builds the RFC 8446 content
        const th: [32]u8 = @splat(3);
        const via_sign = try signer.sign(.client, &th, null, &got);
        try verify(.ed25519, .{ .ed25519 = kp.public_key }, .client, &th, via_sign);
    }
}

test "SecretKey.ed25519_prepared signs as .ed25519 through sign/signContent and negotiates the same scheme" {
    const kp = try kat.ed25519_client.keyPair();
    var signer = try Ed25519Signer.init(&kp.secret_key);
    defer signer.deinit();
    try testing.expectEqualSlices(SignatureScheme, &.{.ed25519}, candidateSchemes(.{ .ed25519_prepared = &signer }));
    try testing.expect(canSign(.{ .ed25519_prepared = &signer }, .ed25519));
    try testing.expect(!canSign(.{ .ed25519_prepared = &signer }, .ecdsa_secp256r1_sha256));
    var want: [64]u8 = undefined;
    var got: [64]u8 = undefined;
    _ = try sign(.ed25519, .{ .ed25519 = &kp.secret_key }, .server, &kat.ed25519_client.transcript_hash, null, &want);
    _ = try sign(.ed25519, .{ .ed25519_prepared = &signer }, .server, &kat.ed25519_client.transcript_hash, null, &got);
    try testing.expectEqualSlices(u8, &want, &got);
    try testing.expectError(error.KeyMismatch, sign(.ecdsa_secp256r1_sha256, .{ .ed25519_prepared = &signer }, .server, &kat.ed25519_client.transcript_hash, null, &got));
    var small: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, sign(.ed25519, .{ .ed25519_prepared = &signer }, .server, &kat.ed25519_client.transcript_hash, null, &small));
}

test "Ed25519Signer: init refuses a key whose public half is not the seed's; short out is BufferTooSmall" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    for (32..64) |i| {
        var bytes = kp.secret_key.toBytes();
        bytes[i] ^= 0x01;
        const bad = try Ed25519.SecretKey.fromBytes(bytes);
        try testing.expectError(error.KeyMismatch, Ed25519Signer.init(&bad));
        try testing.expectError(error.KeyMismatch, Ed25519Signer.initWith(&bad, .every_sign));
    }
    var signer = try Ed25519Signer.init(&kp.secret_key);
    defer signer.deinit();
    var small: [63]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, signer.signContent("m", null, &small));
}

test "Ed25519Signer: .once_at_load trusts the stored public key; .every_sign re-derives it per signature" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(11));
    var out: [64]u8 = undefined;
    var once = try Ed25519Signer.init(&kp.secret_key);
    defer once.deinit();
    var every = try Ed25519Signer.initWith(&kp.secret_key, .every_sign);
    defer every.deinit();
    // Corrupt the stored public half after load (the fault the per-sign
    // check exists for).
    once.public_key[5] ^= 1;
    every.public_key[5] ^= 1;
    try testing.expectError(error.KeyMismatch, every.signContent("m", null, &out));
    _ = try once.signContent("m", null, &out); // not detected: the documented trade-off
}

test "Ed25519 signer: the hedged signature is std's with the same noise, and differs from the deterministic one" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    var p1 = std.Random.DefaultPrng.init(5);
    var p2 = std.Random.DefaultPrng.init(5);
    var noise: [Ed25519.noise_length]u8 = undefined;
    p2.random().bytes(&noise);
    const want = (try kp.sign("hedged", noise)).toBytes();
    var out1: [64]u8 = undefined;
    const got = try signEd25519(&kp.secret_key, "hedged", p1.random(), &out1);
    try testing.expectEqualSlices(u8, &want, got);
    var out2: [64]u8 = undefined;
    const det = try signEd25519(&kp.secret_key, "hedged", null, &out2);
    try testing.expect(!std.mem.eql(u8, got, det));
}

test "uncompressedSec1P256: equals std's for affine and for projective keys" {
    const P = std.crypto.ecc.P256;
    const Pk = Ecdsa.EcdsaP256Sha256.PublicKey;
    var prng = std.Random.DefaultPrng.init(0x256);
    var projective_seen = false;
    for (0..6) |_| {
        var seed: [Ecdsa.EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
        prng.random().bytes(&seed);
        const kp = try Ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
        const affine = try Pk.fromSec1(&kp.public_key.toUncompressedSec1());
        try testing.expect(affine.p.z.equivalent(P.Fe.one));
        try testing.expectEqualSlices(u8, &affine.toUncompressedSec1(), &uncompressedSec1P256(affine));
        // A key whose point is not normalised (z != 1): std's path, same bytes.
        const proj: Pk = .{ .p = affine.p.dbl().dbl() };
        if (!proj.p.z.equivalent(P.Fe.one)) projective_seen = true;
        try testing.expectEqualSlices(u8, &proj.toUncompressedSec1(), &uncompressedSec1P256(proj));
        try testing.expectEqual(@as(u8, 4), uncompressedSec1P256(proj)[0]);
    }
    try testing.expect(projective_seen);
}
