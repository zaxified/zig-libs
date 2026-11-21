// SPDX-License-Identifier: MIT

//! The record-protection states of the handshake and of application traffic:
//! std's `tls.HandshakeCipher` / `tls.ApplicationCipher` (same shape, same
//! field names, same tags) with AES-GCM from the zig-libs `aesgcm` module
//! instead of std's. Zig 0.17 lowers the `u128` arithmetic of std's CTR mode
//! and GHASH to per-byte loops (codeberg ziglang/zig #36256): std AES-128-GCM
//! went from 0.40 G to 1.02 G cycles on 16 KiB messages, while `aesgcm`
//! (std-shaped API, an AES-NI stitched kernel) is unaffected. ChaCha20-Poly1305
//! and AEGIS stay std's.

const std = @import("std");
const crypto = std.crypto;
const aesgcm = @import("aesgcm");

pub fn HandshakeCipherT(comptime AeadType: type, comptime HashType: type, comptime explicit_iv_length: comptime_int) type {
    return struct {
        pub const A = ApplicationCipherT(AeadType, HashType, explicit_iv_length);

        transcript_hash: A.Hash,
        version: union {
            tls_1_2: struct {
                expected_server_verify_data: [A.verify_data_length]u8,
                app_cipher: A.Tls_1_2,
            },
            tls_1_3: struct {
                handshake_secret: [A.Hkdf.prk_length]u8,
                master_secret: [A.Hkdf.prk_length]u8,
                client_handshake_key: [A.AEAD.key_length]u8,
                server_handshake_key: [A.AEAD.key_length]u8,
                client_finished_key: [A.Hmac.key_length]u8,
                server_finished_key: [A.Hmac.key_length]u8,
                client_handshake_iv: [A.AEAD.nonce_length]u8,
                server_handshake_iv: [A.AEAD.nonce_length]u8,
            },
        },
    };
}

pub const HandshakeCipher = union(enum) {
    AES_128_GCM_SHA256: HandshakeCipherT(aesgcm.Aes128Gcm, crypto.hash.sha2.Sha256, 8),
    AES_256_GCM_SHA384: HandshakeCipherT(aesgcm.Aes256Gcm, crypto.hash.sha2.Sha384, 8),
    CHACHA20_POLY1305_SHA256: HandshakeCipherT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256, 0),
    AEGIS_256_SHA512: HandshakeCipherT(crypto.aead.aegis.Aegis256, crypto.hash.sha2.Sha512, 0),
    AEGIS_128L_SHA256: HandshakeCipherT(crypto.aead.aegis.Aegis128L, crypto.hash.sha2.Sha256, 0),
};

pub fn ApplicationCipherT(comptime AeadType: type, comptime HashType: type, comptime explicit_iv_length: comptime_int) type {
    return union {
        pub const AEAD = AeadType;
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);

        pub const enc_key_length = AEAD.key_length;
        pub const fixed_iv_length = AEAD.nonce_length - explicit_iv_length;
        pub const record_iv_length = explicit_iv_length;
        pub const mac_length = AEAD.tag_length;
        pub const mac_key_length = Hmac.key_length_min;
        pub const verify_data_length = 12;

        tls_1_2: Tls_1_2,
        tls_1_3: Tls_1_3,

        pub const Tls_1_2 = extern struct {
            client_write_MAC_key: [mac_key_length]u8,
            server_write_MAC_key: [mac_key_length]u8,
            client_write_key: [enc_key_length]u8,
            server_write_key: [enc_key_length]u8,
            client_write_IV: [fixed_iv_length]u8,
            server_write_IV: [fixed_iv_length]u8,
            // non-standard entropy
            client_salt: [record_iv_length]u8,
        };

        pub const Tls_1_3 = struct {
            client_secret: [Hash.digest_length]u8,
            server_secret: [Hash.digest_length]u8,
            client_key: [AEAD.key_length]u8,
            server_key: [AEAD.key_length]u8,
            client_iv: [AEAD.nonce_length]u8,
            server_iv: [AEAD.nonce_length]u8,
        };
    };
}

/// Encryption parameters for application traffic.
pub const ApplicationCipher = union(enum) {
    AES_128_GCM_SHA256: ApplicationCipherT(aesgcm.Aes128Gcm, crypto.hash.sha2.Sha256, 8),
    AES_256_GCM_SHA384: ApplicationCipherT(aesgcm.Aes256Gcm, crypto.hash.sha2.Sha384, 8),
    CHACHA20_POLY1305_SHA256: ApplicationCipherT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256, 0),
    AEGIS_256_SHA512: ApplicationCipherT(crypto.aead.aegis.Aegis256, crypto.hash.sha2.Sha512, 0),
    AEGIS_128L_SHA256: ApplicationCipherT(crypto.aead.aegis.Aegis128L, crypto.hash.sha2.Sha256, 0),
};

test "the unions keep std's tags in std's order" {
    inline for (.{ .{ HandshakeCipher, crypto.tls.HandshakeCipher }, .{ ApplicationCipher, crypto.tls.ApplicationCipher } }) |p| {
        const ours = comptime std.meta.fieldNames(p[0]);
        const theirs = comptime std.meta.fieldNames(p[1]);
        try std.testing.expectEqual(theirs.len, ours.len);
        inline for (ours, theirs) |a, b| try std.testing.expectEqualStrings(b, a);
    }
    try std.testing.expect(@FieldType(ApplicationCipher, "AES_128_GCM_SHA256").AEAD == aesgcm.Aes128Gcm);
    try std.testing.expect(@FieldType(HandshakeCipher, "AES_256_GCM_SHA384").A.AEAD == aesgcm.Aes256Gcm);
}
