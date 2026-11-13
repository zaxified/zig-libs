// SPDX-License-Identifier: MIT

//! dtls.suite12 — the DTLS 1.2 cipher suites the 1.2 engine wires and the
//! protocol-version enum `Config.versions` takes.
//!
//! Deliberately AEAD-only and forward-secret or PSK: no CBC (RFC 7457's
//! Lucky13/POODLE family), no static-RSA key exchange (no forward secrecy,
//! Bleichenbacher), no CCM (no 12-byte-nonce CCM core in this repo yet —
//! SPEC Backlog).

const std = @import("std");
const record12 = @import("record12.zig");
const HashAlg = @import("suitehash.zig").HashAlg;

/// The DTLS versions a `Config` may enable (`Config.versions`).
pub const ProtocolVersion = enum {
    /// RFC 6347.
    dtls12,
    /// RFC 9147.
    dtls13,
};

/// How a 1.2 suite establishes its premaster secret.
pub const KeyExchange12 = enum {
    /// RFC 8422 §2.1, ECDSA- (or EdDSA-, RFC 8422 §5.1.1) signed ECDHE.
    ecdhe_ecdsa,
    /// RFC 8422 §2.2 (RFC 5289), RSA-signed ECDHE.
    ecdhe_rsa,
    /// RFC 4279 §2: plain PSK, no (EC)DHE.
    psk,
    /// RFC 5489 §2: ECDHE authenticated by the PSK.
    ecdhe_psk,

    pub fn isPsk(self: KeyExchange12) bool {
        return self == .psk or self == .ecdhe_psk;
    }
    pub fn usesEcdhe(self: KeyExchange12) bool {
        return self != .psk;
    }
    pub fn usesCertificate(self: KeyExchange12) bool {
        return self == .ecdhe_ecdsa or self == .ecdhe_rsa;
    }
};

/// IANA TLS cipher-suite registry values (RFC 5289 §3.2, RFC 7905 §2,
/// RFC 5487 §3.1 for PSK-AES-GCM, RFC 7905 §2 for ECDHE-PSK-ChaCha).
pub const CipherSuite12 = enum(u16) {
    ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_ecdsa_with_chacha20_poly1305_sha256 = 0xcca9,
    ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xcca8,
    psk_with_aes_128_gcm_sha256 = 0x00a8,
    ecdhe_psk_with_chacha20_poly1305_sha256 = 0xccac,
    _,

    /// Null for a value this module does not wire.
    pub fn keyExchange(self: CipherSuite12) ?KeyExchange12 {
        return switch (self) {
            .ecdhe_ecdsa_with_aes_128_gcm_sha256, .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_ecdsa_with_chacha20_poly1305_sha256 => .ecdhe_ecdsa,
            .ecdhe_rsa_with_aes_128_gcm_sha256, .ecdhe_rsa_with_aes_256_gcm_sha384, .ecdhe_rsa_with_chacha20_poly1305_sha256 => .ecdhe_rsa,
            .psk_with_aes_128_gcm_sha256 => .psk,
            .ecdhe_psk_with_chacha20_poly1305_sha256 => .ecdhe_psk,
            _ => null,
        };
    }

    pub fn bulk(self: CipherSuite12) record12.Bulk {
        return switch (self) {
            .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_rsa_with_aes_256_gcm_sha384 => .aes_256_gcm,
            .ecdhe_ecdsa_with_chacha20_poly1305_sha256, .ecdhe_rsa_with_chacha20_poly1305_sha256, .ecdhe_psk_with_chacha20_poly1305_sha256 => .chacha20_poly1305,
            else => .aes_128_gcm,
        };
    }

    /// The PRF / transcript hash (RFC 5288 §3, RFC 5289 §3.2: `_SHA384`
    /// suites use SHA-384; RFC 7905 §2: the ChaCha suites SHA-256).
    pub fn hash(self: CipherSuite12) HashAlg {
        return switch (self) {
            .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_rsa_with_aes_256_gcm_sha384 => .sha384,
            else => .sha256,
        };
    }

    pub fn isWired(self: CipherSuite12) bool {
        return self.keyExchange() != null;
    }
};

/// `Config.cipher_suites12`'s default, in pion/dtls's order: ECDSA first,
/// AES-128-GCM before AES-256-GCM before ChaCha20, then RSA, then PSK. A
/// connection uses only the ones its `Config.key_exchange` allows.
pub const default_suites = [_]CipherSuite12{
    .ecdhe_ecdsa_with_aes_128_gcm_sha256,
    .ecdhe_ecdsa_with_aes_256_gcm_sha384,
    .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    .ecdhe_rsa_with_aes_128_gcm_sha256,
    .ecdhe_rsa_with_aes_256_gcm_sha384,
    .ecdhe_rsa_with_chacha20_poly1305_sha256,
    .psk_with_aes_128_gcm_sha256,
    .ecdhe_psk_with_chacha20_poly1305_sha256,
};

/// The groups the 1.2 engine offers for ECDHE (RFC 8422 §5.1.1), most
/// preferred first. The post-quantum hybrid is a TLS 1.3 construction and
/// has no DTLS 1.2 form.
pub const groups12 = [_]u16{ 0x001d, 0x0017, 0x0018 };

test "suite12: every default suite is wired and has the RFC's hash and AEAD" {
    for (default_suites) |s| try std.testing.expect(s.isWired());
    try std.testing.expectEqual(HashAlg.sha384, CipherSuite12.ecdhe_rsa_with_aes_256_gcm_sha384.hash());
    try std.testing.expectEqual(record12.Bulk.chacha20_poly1305, CipherSuite12.ecdhe_psk_with_chacha20_poly1305_sha256.bulk());
    const unknown: CipherSuite12 = @fromBackingInt(0x002f); // TLS_RSA_WITH_AES_128_CBC_SHA — deliberately not wired
    try std.testing.expect(!unknown.isWired());
}
