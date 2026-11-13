// SPDX-License-Identifier: MIT

//! dtls.sig12 — `digitally-signed` (RFC 5246 §4.7) for the DTLS 1.2 engine:
//! the ServerKeyExchange signature (RFC 8422 §5.4, over `client_random +
//! server_random + ServerECDHParams`) and the CertificateVerify signature
//! (RFC 5246 §7.4.8, over the raw `handshake_messages`).
//!
//! TLS 1.2 signs the CONTENT itself with the scheme's hash, with no TLS 1.3
//! context prefix, so this routes `tls13.certverify.signContent` /
//! `verifyContent` for every scheme that module has, and adds the two
//! PKCS#1 v1.5 schemes TLS 1.2 peers still use (`rsa_pkcs1_sha256` 0x0401,
//! `rsa_pkcs1_sha384` 0x0501, RFC 8446 §4.2.3's legacy code points) through
//! the `rsa` module. They exist here and NOT in the 1.3 engine: RFC 8446
//! §4.2.3 forbids PKCS#1 v1.5 for TLS 1.3 handshake signatures. RSA-PSS is
//! still preferred whenever the peer offers it (`preferred_schemes` order).

const std = @import("std");
const rsa = @import("rsa");
const certverify = @import("tls13").certverify;

pub const rsa_pkcs1_sha256: u16 = 0x0401;
pub const rsa_pkcs1_sha384: u16 = 0x0501;

pub const SignError = certverify.SignError;
pub const VerifyError = error{CertVerifyFailed};

/// What this side advertises in `signature_algorithms` (RFC 5246
/// §7.4.1.4.1) when 1.2 is offered: every scheme `Config.signature_algorithms`
/// lists, followed by the two PKCS#1 v1.5 ones — so they are only ever a
/// fallback for a peer that offered nothing better.
pub const pkcs1_schemes = [_]u16{ rsa_pkcs1_sha256, rsa_pkcs1_sha384 };

pub fn isPkcs1(scheme: u16) bool {
    return scheme == rsa_pkcs1_sha256 or scheme == rsa_pkcs1_sha384;
}

/// True when `sk` can produce a `scheme` signature.
pub fn canSign(sk: certverify.SecretKey, scheme: u16) bool {
    if (isPkcs1(scheme)) return std.meta.activeTag(sk) == .rsa;
    return certverify.canSign(sk, @fromBackingInt(scheme));
}

/// Signs `content` under `scheme`. PKCS#1 v1.5 runs the private operation
/// with base blinding from `random` (the signature does not depend on it).
// secret-api-ok: `SecretKey` is a tagged union of pointers to the key; the signers run under their own burns.
pub fn sign(scheme: u16, sk: certverify.SecretKey, content: []const u8, random: std.Random, out: []u8) SignError![]u8 {
    if (isPkcs1(scheme)) {
        const k = switch (sk) {
            .rsa => |k| k,
            else => return error.KeyMismatch,
        };
        const r = if (scheme == rsa_pkcs1_sha256)
            rsa.signPkcs1v15Blinded(k, std.crypto.hash.sha2.Sha256, .{ .csprng = random }, content, out)
        else
            rsa.signPkcs1v15Blinded(k, std.crypto.hash.sha2.Sha384, .{ .csprng = random }, content, out);
        return r catch |err| switch (err) {
            error.FaultDetected => error.FaultDetected,
            error.EntropyFailure => error.EntropyFailure,
            else => error.BufferTooSmall,
        };
    }
    return certverify.signContent(@fromBackingInt(scheme), sk, content, random, out);
}

/// Verifies a peer's signature over `content`. Every failure — unknown
/// scheme, key/scheme mismatch, bad signature — is the one
/// `error.CertVerifyFailed` (no oracle on which).
pub fn verify(scheme: u16, pk: certverify.PublicKey, content: []const u8, signature: []const u8) VerifyError!void {
    if (isPkcs1(scheme)) {
        const k = switch (pk) {
            .rsa => |k| k,
            else => return error.CertVerifyFailed,
        };
        const r = if (scheme == rsa_pkcs1_sha256)
            rsa.verifyPkcs1v15(k, std.crypto.hash.sha2.Sha256, content, signature)
        else
            rsa.verifyPkcs1v15(k, std.crypto.hash.sha2.Sha384, content, signature);
        r catch return error.CertVerifyFailed;
        return;
    }
    certverify.verifyContent(@fromBackingInt(scheme), pk, content, signature) catch return error.CertVerifyFailed;
}

pub fn maxSignatureLen() usize {
    return certverify.maxSignatureLen(.rsa_pss_rsae_sha256);
}
