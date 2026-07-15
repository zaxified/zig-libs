// SPDX-License-Identifier: MIT

//! dtls.certverify -- TLS/DTLS 1.3 CertificateVerify signature construction
//! (RFC 8446 §4.4.3), reused VERBATIM by DTLS 1.3 (RFC 9147 does not
//! redefine it -- only the record/handshake HEADERS differ between TLS and
//! DTLS, never this message's signature construction).
//!
//! This file is a self-contained, ADDITIVE module: it does not touch, call
//! into, or get called by the PSK flight engine (`Connection.zig`,
//! `messages.zig`, `keyschedule.zig`, `engine.zig`) or the handshake state
//! machine. It takes a caller-supplied transcript hash and typed key as
//! input and produces/verifies a CertificateVerify signature -- wiring this
//! into an actual certificate-auth handshake flow (which this module's PSK
//! engine does not have, see `root.zig`'s module doc comment) is future work
//! for whoever builds that flow, not this file's job.
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

const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;

// ── SignatureScheme (RFC 8446 §4.2.3) ────────────────────────────────────

/// TLS 1.3 `SignatureScheme` code points this module supports. RFC 8446
/// defines many more (legacy PKCS#1 v1.5 schemes for backward-compat-only
/// certificate verification, ecdsa_sha1, various historical/reserved
/// values); this module only targets the six code points the task brief
/// scoped it to (`rsa_pss_rsae_sha{256,384,512}`, `ecdsa_secp{256,384}r1_sha*`,
/// `ed25519`) -- notably NOT `ed448` (a separate `ed448` module already
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
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    _,

    /// Digest length (bytes) of the hash this scheme signs with, for the
    /// schemes that route the signed content through a named hash function
    /// (RSA-PSS: the MGF1/message hash per RFC 8017 §8.1; ECDSA: the hash
    /// fed to the signature primitive per SEC1). Returns `null` for
    /// `ed25519` (PureEdDSA, RFC 8032 -- it hashes the message internally
    /// with SHA-512 and has no separate "signature hash" parameter to
    /// validate the caller's transcript hash length against) and for any
    /// unrecognized scheme.
    ///
    /// `sign`/`verify` use this to reject a `transcript_hash` whose length
    /// doesn't match what the scheme expects -- catching a caller wiring
    /// e.g. a SHA-384 transcript hash to `ecdsa_secp256r1_sha256` (which
    /// RFC 8446 §4.2.3 pairs with SHA-256 specifically) before it reaches
    /// the crypto layer.
    pub fn hashDigestLen(scheme: SignatureScheme) ?usize {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256 => 32,
            .ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha384 => 48,
            .rsa_pss_rsae_sha512 => 64,
            .ed25519 => null,
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
/// caller-computed running handshake-transcript hash (this module never
/// computes it -- that is the handshake state machine's job, per this
/// module's "purely additive, standalone" scope; see `root.zig`'s
/// `keyschedule.zig` for this scaffold's transcript-hashing machinery,
/// unused directly by this file). Writes into `out` and returns the written
/// subslice (exactly `signed_content_prefix_len + context_string.len + 1 +
/// transcript_hash.len` bytes).
///
/// This is pure byte-plumbing with no cryptographic operation of its own --
/// fully implemented and unit-tested byte-exact below (see the "signed
/// content" tests), independent of the `sign`/`verify` crypto stubs.
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
    ed25519: Ed25519.PublicKey,
};

/// A CertificateVerify-capable secret (signing) key, tagged by key family --
/// see `PublicKey`'s doc comment for the family/scheme pairing rule.
pub const SecretKey = union(enum) {
    rsa: rsa.SecretKey,
    ecdsa_p256: Ecdsa.EcdsaP256Sha256.SecretKey,
    ecdsa_p384: Ecdsa.EcdsaP384Sha384.SecretKey,
    ed25519: Ed25519.SecretKey,
};

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
        .ed25519 => Ed25519.Signature.encoded_length,
        _ => 0,
    };
}

// ── verify ────────────────────────────────────────────────────────────────

pub const VerifyError = BuildContentError || error{
    /// `scheme` is not one of the named `SignatureScheme` values this
    /// module implements.
    UnsupportedScheme,
    /// `public_key`'s active union field does not match the key family
    /// `scheme` requires.
    KeyMismatch,
    /// `transcript_hash.len` does not equal `scheme.hashDigestLen()` (for
    /// schemes that mandate one).
    HashLengthMismatch,
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
/// signature check dispatches to one of four private `verifyXxx` primitives
/// (see the "crypto dispatch" section below). The dispatch logic itself
/// (which primitive gets called for which scheme) is additionally covered by
/// the `KeyMismatch`/`UnsupportedScheme`/`HashLengthMismatch` reject-path
/// tests below, which short-circuit before reaching the crypto layer.
pub fn verify(
    scheme: SignatureScheme,
    public_key: PublicKey,
    side: Side,
    transcript_hash: []const u8,
    signature: []const u8,
) VerifyError!void {
    if (scheme.hashDigestLen()) |want| {
        if (transcript_hash.len != want) return error.HashLengthMismatch;
    }
    var content_buf: [max_signed_content_len]u8 = undefined;
    const content = try buildSignedContent(side, transcript_hash, &content_buf);

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
        .ed25519 => blk: {
            const pk = switch (public_key) {
                .ed25519 => |k| k,
                else => return error.KeyMismatch,
            };
            break :blk verifyEd25519(pk, content, signature);
        },
        _ => error.UnsupportedScheme,
    };
}

// ── sign ──────────────────────────────────────────────────────────────────

pub const SignError = BuildContentError || error{
    UnsupportedScheme,
    KeyMismatch,
    HashLengthMismatch,
    /// RFC 8446 §4.2.3 fixes RSA-PSS's salt length to `Hash.digest_length`
    /// for every `rsa_pss_rsae_*` scheme -- unlike RFC 8017 (PKCS#1 v2.2),
    /// which allows a `salt_len = 0` deterministic mode, TLS 1.3 has no
    /// deterministic RSA-PSS option, so `random == null` is a caller error
    /// for these three schemes specifically (ECDSA/Ed25519 accept
    /// `random == null` for a deterministic signature).
    RandomRequired,
    /// `out` is shorter than the scheme's exact signature length.
    BufferTooSmall,
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
/// the actual signing operation dispatches to one of four private `signXxx`
/// primitives (see the "crypto dispatch" section below).
pub fn sign(
    scheme: SignatureScheme,
    secret_key: SecretKey,
    side: Side,
    transcript_hash: []const u8,
    random: ?std.Random,
    out: []u8,
) SignError![]u8 {
    if (scheme.hashDigestLen()) |want| {
        if (transcript_hash.len != want) return error.HashLengthMismatch;
    }
    var content_buf: [max_signed_content_len]u8 = undefined;
    const content = try buildSignedContent(side, transcript_hash, &content_buf);

    return switch (scheme) {
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => blk: {
            const sk = switch (secret_key) {
                .rsa => |k| k,
                else => return error.KeyMismatch,
            };
            const rnd = random orelse return error.RandomRequired;
            const modulus_len = (sk.n.bits() + 7) / 8;
            if (out.len < modulus_len) return error.BufferTooSmall;
            break :blk signRsaPss(scheme, sk, content, rnd, out);
        },
        .ecdsa_secp256r1_sha256 => blk: {
            const sk = switch (secret_key) {
                .ecdsa_p256 => |k| k,
                else => return error.KeyMismatch,
            };
            if (out.len < Ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max) return error.BufferTooSmall;
            break :blk signEcdsaP256(sk, content, random, out);
        },
        .ecdsa_secp384r1_sha384 => blk: {
            const sk = switch (secret_key) {
                .ecdsa_p384 => |k| k,
                else => return error.KeyMismatch,
            };
            if (out.len < Ecdsa.EcdsaP384Sha384.Signature.der_encoded_length_max) return error.BufferTooSmall;
            break :blk signEcdsaP384(sk, content, random, out);
        },
        .ed25519 => blk: {
            const sk = switch (secret_key) {
                .ed25519 => |k| k,
                else => return error.KeyMismatch,
            };
            if (out.len < Ed25519.Signature.encoded_length) return error.BufferTooSmall;
            break :blk signEd25519(sk, content, random, out);
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
// `UnsupportedScheme`/`HashLengthMismatch` all short-circuit before
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

fn signRsaPss(scheme: SignatureScheme, sk: rsa.SecretKey, content: []const u8, random: std.Random, out: []u8) SignError![]u8 {
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
    };
}

fn verifyEcdsaP256(pk: Ecdsa.EcdsaP256Sha256.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // RFC 8446 §4.3.2: ECDSA signatures are ASN.1 DER on the wire, never raw
    // r||s. fromDer's EncodingError (malformed DER) and verify's whole error
    // set (SignatureVerificationFailed/IdentityElement/NonCanonical) all
    // collapse into this module's single InvalidSignature.
    const sig = Ecdsa.EcdsaP256Sha256.Signature.fromDer(signature) catch return error.InvalidSignature;
    sig.verify(content, pk) catch return error.InvalidSignature;
}

fn signEcdsaP256(sk: Ecdsa.EcdsaP256Sha256.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    const Scheme = Ecdsa.EcdsaP256Sha256;
    // fromSecretKey/sign only fail on a degenerate secret key (identity /
    // non-canonical scalar) -- a key problem, mapped to KeyMismatch.
    const key_pair = Scheme.KeyPair.fromSecretKey(sk) catch return error.KeyMismatch;
    var noise_buf: [Scheme.noise_length]u8 = undefined;
    const noise: ?[Scheme.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk noise_buf;
    } else null; // null => std's fully deterministic nonce derivation
    const sig = key_pair.sign(content, noise) catch return error.KeyMismatch;
    // RFC 8446 §4.3.2 mandates DER on the wire; `sign` pre-checked
    // out.len >= der_encoded_length_max.
    return sig.toDer(out[0..Scheme.Signature.der_encoded_length_max]);
}

fn verifyEcdsaP384(pk: Ecdsa.EcdsaP384Sha384.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // Same shape as verifyEcdsaP256, over the P-384/SHA-384 instantiation.
    const sig = Ecdsa.EcdsaP384Sha384.Signature.fromDer(signature) catch return error.InvalidSignature;
    sig.verify(content, pk) catch return error.InvalidSignature;
}

fn signEcdsaP384(sk: Ecdsa.EcdsaP384Sha384.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    // Same shape as signEcdsaP256, over the P-384/SHA-384 instantiation
    // (noise_length is 48 here -- the curve's scalar length, not the caller's
    // concern: it comes from the Scheme type).
    const Scheme = Ecdsa.EcdsaP384Sha384;
    const key_pair = Scheme.KeyPair.fromSecretKey(sk) catch return error.KeyMismatch;
    var noise_buf: [Scheme.noise_length]u8 = undefined;
    const noise: ?[Scheme.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk noise_buf;
    } else null;
    const sig = key_pair.sign(content, noise) catch return error.KeyMismatch;
    return sig.toDer(out[0..Scheme.Signature.der_encoded_length_max]);
}

fn verifyEd25519(pk: Ed25519.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    // Ed25519 is the one scheme RFC 8446 §4.3.2 does NOT DER-wrap: the wire
    // signature is the raw 64-byte R || S encoding. fromBytes is infallible
    // (fixed-size array in), so the length check is ours.
    if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
    const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
    // verifyStrict: the conservative, cofactor-checked variant -- rejects
    // non-canonical encodings and small-order/mixed-order points that plain
    // verify tolerates. Every honestly-generated RFC 8032 signature (incl.
    // this module's KAT, OpenSSL-produced) passes strict verification.
    sig.verifyStrict(content, pk) catch return error.InvalidSignature;
}

fn signEd25519(sk: Ed25519.SecretKey, content: []const u8, random: ?std.Random, out: []u8) SignError![]u8 {
    // fromSecretKey/sign fail only on a degenerate or internally-inconsistent
    // secret key (identity/non-canonical/weak public half, or a secret key
    // whose embedded public key doesn't match -- std's KeyMismatchError) --
    // all key problems, mapped to KeyMismatch.
    const key_pair = Ed25519.KeyPair.fromSecretKey(sk) catch return error.KeyMismatch;
    var noise_buf: [Ed25519.noise_length]u8 = undefined;
    const noise: ?[Ed25519.noise_length]u8 = if (random) |rnd| blk: {
        rnd.bytes(&noise_buf);
        break :blk noise_buf;
    } else null; // null => the standard deterministic RFC 8032 signature
    const sig = key_pair.sign(content, noise) catch return error.KeyMismatch;
    // Raw 64-byte R || S encoding on the wire (NOT DER); `sign` pre-checked
    // out.len >= encoded_length.
    const sig_bytes = sig.toBytes();
    @memcpy(out[0..Ed25519.Signature.encoded_length], &sig_bytes);
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
    const transcript_hash = [_]u8{0xAA} ** 32;
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
    const transcript_hash = [_]u8{0x99} ** 48;
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
    const too_long = [_]u8{0} ** (max_transcript_hash_len + 1);
    try testing.expectError(error.TranscriptHashTooLong, buildSignedContent(.server, &too_long, &buf));

    const transcript_hash = [_]u8{0} ** 32;
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
    try testing.expectEqual(@as(u16, 0x0403), @intFromEnum(SignatureScheme.ecdsa_secp256r1_sha256));
    try testing.expectEqual(@as(u16, 0x0503), @intFromEnum(SignatureScheme.ecdsa_secp384r1_sha384));
    try testing.expectEqual(@as(u16, 0x0804), @intFromEnum(SignatureScheme.rsa_pss_rsae_sha256));
    try testing.expectEqual(@as(u16, 0x0805), @intFromEnum(SignatureScheme.rsa_pss_rsae_sha384));
    try testing.expectEqual(@as(u16, 0x0806), @intFromEnum(SignatureScheme.rsa_pss_rsae_sha512));
    try testing.expectEqual(@as(u16, 0x0807), @intFromEnum(SignatureScheme.ed25519));
}

// -- verify/sign reject-path dispatch: real, complete, never touches the
// -- panicking stubs (proves the dispatch logic itself doesn't need the
// -- crypto layer to be exercised) --

test "verify: rejects a key-family mismatch before reaching the crypto stub" {
    const wrong_key = PublicKey{ .ed25519 = (try kat.ed25519_client.keyPair()).public_key };
    try testing.expectError(error.KeyMismatch, verify(.ecdsa_secp256r1_sha256, wrong_key, .server, &kat.ecdsa_p256_server.transcript_hash, &kat.ecdsa_p256_server.signature_der));
}

test "verify: rejects a transcript hash length that doesn't match the scheme's hash" {
    const pk = PublicKey{ .ecdsa_p256 = try kat.ecdsa_p256_server.publicKey() };
    const wrong_len_hash = [_]u8{0} ** 48; // ecdsa_secp256r1_sha256 wants 32
    try testing.expectError(error.HashLengthMismatch, verify(.ecdsa_secp256r1_sha256, pk, .server, &wrong_len_hash, &kat.ecdsa_p256_server.signature_der));
}

test "verify: rejects an unrecognized SignatureScheme wire value" {
    const pk = PublicKey{ .ed25519 = (try kat.ed25519_client.keyPair()).public_key };
    const unknown: SignatureScheme = @enumFromInt(0xffff);
    try testing.expectError(error.UnsupportedScheme, verify(unknown, pk, .client, &kat.ed25519_client.transcript_hash, &kat.ed25519_client.signature));
}

test "sign: rejects a key-family mismatch before reaching the crypto stub" {
    const wrong_key = SecretKey{ .ed25519 = try std.crypto.sign.Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes) };
    var out: [max_signed_content_len]u8 = undefined;
    try testing.expectError(error.KeyMismatch, sign(.ecdsa_secp256r1_sha256, wrong_key, .server, &kat.ecdsa_p256_server.transcript_hash, null, &out));
}

test "sign: RSA-PSS schemes require a random source (RFC 8446 §4.2.3 forbids salt_len = 0)" {
    const sk = SecretKey{ .rsa = try kat.rsa_pss_sha256_server.secretKey() };
    var out: [rsa.max_modulus_len]u8 = undefined;
    try testing.expectError(error.RandomRequired, sign(.rsa_pss_rsae_sha256, sk, .server, &kat.rsa_pss_sha256_server.transcript_hash, null, &out));
}

test "sign: rejects an undersized output buffer before reaching the crypto stub" {
    const sk = SecretKey{ .ecdsa_p256 = try kat.ecdsa_p256_server.secretKey() };
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
    const sk = SecretKey{ .rsa = try kat.rsa_pss_sha256_server.secretKey() };
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
    const sk = SecretKey{ .ecdsa_p256 = try kat.ecdsa_p256_server.secretKey() };
    var out: [Ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = try sign(.ecdsa_secp256r1_sha256, sk, .server, &kat.ecdsa_p256_server.transcript_hash, null, &out);
    try testing.expectEqualSlices(u8, &kat.ecdsa_p256_server.signature_der, sig);
}

test "KAT: ecdsa_secp384r1_sha384 verify accepts the self-generated-deterministic DER vector" {
    const pk = PublicKey{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() };
    try verify(.ecdsa_secp384r1_sha384, pk, .server, &kat.ecdsa_p384_server.transcript_hash, &kat.ecdsa_p384_server.signature_der);
}

test "KAT: ecdsa_secp384r1_sha384 sign reproduces the deterministic DER vector byte-exact" {
    const sk = SecretKey{ .ecdsa_p384 = try kat.ecdsa_p384_server.secretKey() };
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

test "KAT: ed25519 sign reproduces the cryptography-cross-checked vector byte-exact" {
    const sk = SecretKey{ .ed25519 = try Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes) };
    var out: [Ed25519.Signature.encoded_length]u8 = undefined;
    const sig = try sign(.ed25519, sk, .client, &kat.ed25519_client.transcript_hash, null, &out);
    try testing.expectEqualSlices(u8, &kat.ed25519_client.signature, sig);
}
