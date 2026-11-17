// SPDX-License-Identifier: MIT
//! mls.suite — RFC 9420 §5.1/§17.1 Cipher Suites: the named bundle of
//! (KEM, KDF, AEAD, Hash, Signature) algorithms an MLS session picks once
//! and uses for every group-key computation. `CipherSuite(...)` is a
//! comptime type constructor; every suite in `supported` is an
//! instantiation of it, and the rest of the module is generic over the
//! instantiation (`comptime S: type`). Suite choice is therefore a
//! compile-time decision of the caller, the way OpenMLS and mls-rs bind a
//! crypto provider: a `Welcome`/`GroupInfo` naming a different suite than
//! the one the caller instantiated is refused (`error.CipherSuiteMismatch`)
//! exactly as before more suites existed. A registry suite missing from
//! `supported` is not instantiated; the X448/Ed448 pair (`0x0004`/`0x0006`)
//! cannot be until the sibling `hpke` module provides an X448 KEM.
//!
//! `0x0001` = `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`: DHKEM(X25519,
//! HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM (all three supplied by the
//! sibling `hpke` module's `X25519Kem`/`schedule` machinery — MLS's own
//! HPKE usage IS `hpke`, not a reimplementation of it, see
//! `EncryptWithLabel`/`DecryptWithLabel` in `crypto.zig`) + SHA-256 (the
//! MLS transcript/ref-hash algorithm, RFC 9420 §5.1 Table 5's "HASH"
//! column) + Ed25519 (`std.crypto.sign.Ed25519`, RFC 9420 §5.1.1's EdDSA
//! public-key format, RFC 8032).
//!
//! Model: RFC 9420 §5.1 (Cipher Suites) + §17.1 (the suite registry table,
//! `0x0001`'s row).

const std = @import("std");
const hpke = @import("hpke");
const aesgcm = @import("aesgcm");

/// RFC 9420 §17.1's registry — every suite name IANA has assigned a
/// `CipherSuite` value to. The ones this module instantiates are listed in
/// `supported`; the others are named here so a `CipherSuiteId` read off
/// the wire prints/compares against its real registry name, matching the
/// non-exhaustive-enum convention this repo's other wire-format id types
/// follow (`hpke.suite.KemId`, `dtls.messages.HandshakeType`).
pub const CipherSuiteId = enum(u16) {
    mls_128_dhkemx25519_aes128gcm_sha256_ed25519 = 0x0001,
    mls_128_dhkemp256_aes128gcm_sha256_p256 = 0x0002,
    mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519 = 0x0003,
    mls_256_dhkemx448_aes256gcm_sha512_ed448 = 0x0004,
    mls_256_dhkemp521_aes256gcm_sha512_p521 = 0x0005,
    mls_256_dhkemx448_chacha20poly1305_sha512_ed448 = 0x0006,
    mls_256_dhkemp384_aes256gcm_sha384_p384 = 0x0007,
    _,
};

/// A fully-wired MLS cipher suite: the KEM (an `hpke`-shaped KEM type —
/// `hpke.X25519Kem`/`hpke.P256Kem` today), the AEAD (a `std.crypto.aead.*`
/// type, matching `hpke`'s own `Context(Aead, Nh)` convention), the KDF
/// (a `std.crypto.kdf.hkdf.Hkdf(Hmac)` instantiation — `Hkdf.expand`/
/// `.extractInit` are called DIRECTLY by `crypto.zig`'s `ExpandWithLabel`/
/// `RefHash`, not through `hpke`'s own `LabeledExtract`/`LabeledExpand`,
/// which fold in HPKE's OWN "HPKE-v1"+suite_id framing — MLS's
/// `KDFLabel`/`RefHashInput` are a separate, MLS-owned wire encoding, see
/// `crypto.zig`'s module doc comment), the Hash (MLS's transcript/ref-hash
/// algorithm — `std.crypto.hash.sha2.Sha256` etc.), and the Signature
/// scheme (a `std.crypto.sign.*`-shaped namespace exposing `KeyPair`/
/// `PublicKey`/`Signature`, with `Signature.encoded_length`).
///
/// Every width constant (`Nh`/`Nk`/`Nn`/`Nx`) is DERIVED from the
/// component types, never independently declared — so a suite is
/// internally consistent by construction, the same discipline `hpke`'s
/// own `Context(Aead, Nh)` follows.
pub fn CipherSuite(
    comptime Kem_: type,
    comptime Aead_: type,
    comptime Hkdf_: type,
    comptime Hash_: type,
    comptime Sig_: type,
    comptime id_: CipherSuiteId,
) type {
    return struct {
        pub const Kem = Kem_;
        pub const Aead = Aead_;
        pub const Hkdf = Hkdf_;
        pub const Hash = Hash_;
        /// The signature scheme's NAMESPACE (e.g. `std.crypto.sign.Ed25519`
        /// itself, not just its `KeyPair`) — exposes `.KeyPair`,
        /// `.PublicKey`, `.Signature` the way `std.crypto.sign.Ed25519`
        /// does.
        pub const Sig = Sig_;
        /// MLS's MAC function — RFC 9420 §17.1's text under Table 7: "All
        /// of the non-GREASE cipher suites use HMAC [RFC2104] as their MAC
        /// function, with different hashes per cipher suite." DERIVED from
        /// `Hash` (never independently declared), so a suite's
        /// `confirmation_tag`/`membership_tag` MAC can't drift from its
        /// transcript hash. Used by `keyschedule.confirmationTag`/
        /// `membershipTag` (RFC 9420 §6.1).
        pub const Mac = std.crypto.auth.hmac.Hmac(Hash_);
        pub const id = id_;

        /// `KDF.Nh` — the KDF's PRK/hash output width in bytes (RFC 9420
        /// §8's `ExpandWithLabel`/`DeriveSecret`; also the module-wide
        /// "secret size" for `init_secret`/epoch secrets/etc. in later
        /// parts).
        pub const Nh = Hkdf.prk_length;
        /// `AEAD.Nk` — the AEAD key width in bytes.
        pub const Nk = Aead.key_length;
        /// `AEAD.Nn` — the AEAD nonce width in bytes.
        pub const Nn = Aead.nonce_length;
        /// `MAC.Nm` — the MAC output width in bytes (RFC 9420 §6.1's
        /// `MAC` type; HMAC's output is its hash's digest length).
        pub const Nm = Mac.mac_length;
        /// The signature scheme's encoded-signature width in bytes (RFC
        /// 9420 §5.1.2: EdDSA signatures are `R || S`; ECDSA signatures
        /// are DER, so `Nx` is suite-specific — not named directly by the
        /// RFC, kept here as a derived convenience the way `Nh`/`Nk`/`Nn`
        /// are).
        pub const Nx = Sig.Signature.encoded_length;

        /// MLS's transcript/ref-hash digest, `Hash(data)` — a one-shot
        /// convenience over `std.crypto.hash.*`'s `Hasher.hash`.
        pub fn hash(data: []const u8) [Hash.digest_length]u8 {
            var out: [Hash.digest_length]u8 = undefined;
            Hash.hash(data, &out, .{});
            return out;
        }
    };
}

/// RFC 9420 §16.1's mandatory-to-implement suite. `hpke.X25519Kem` + `aesgcm
/// .Aes128Gcm` + `std.crypto.kdf.hkdf.HkdfSha256` + `std.crypto.hash.sha2
/// .Sha256` + `std.crypto.sign.Ed25519` reproduce `0x0001`'s five
/// algorithms exactly (see this file's module doc comment).
pub const Mls128X25519Aes128GcmSha256Ed25519 = CipherSuite(
    hpke.X25519Kem,
    aesgcm.Aes128Gcm,
    std.crypto.kdf.hkdf.HkdfSha256,
    std.crypto.hash.sha2.Sha256,
    std.crypto.sign.Ed25519,
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
);

/// `0x0003` = `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`: the
/// mandatory suite with ChaCha20-Poly1305 in place of AES-128-GCM — the
/// choice for hosts without AES instructions. The AEAD is the sibling
/// `chachapoly` module's (re-exported by `hpke` as `hpke.ChaCha20Poly1305`,
/// byte-exact to std's and differentially anchored there), so the HPKE
/// seal/open of §5.1.3 and the content/sender-data AEAD of §6.3 run the
/// same implementation.
pub const Mls128X25519ChaCha20Poly1305Sha256Ed25519 = CipherSuite(
    hpke.X25519Kem,
    hpke.ChaCha20Poly1305,
    std.crypto.kdf.hkdf.HkdfSha256,
    std.crypto.hash.sha2.Sha256,
    std.crypto.sign.Ed25519,
    .mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519,
);

/// The suite a caller with no suite-negotiation needs of its own should
/// reach for first — RFC 9420 §16.1's mandatory-to-implement `0x0001`.
pub const default = Mls128X25519Aes128GcmSha256Ed25519;

/// Every suite this module instantiates, in registry order. The official
/// interop vectors are driven once per entry (`kat_*_test.zig`), so adding
/// a suite here is what puts it under every vector file.
pub const supported = .{
    Mls128X25519Aes128GcmSha256Ed25519,
    Mls128X25519ChaCha20Poly1305Sha256Ed25519,
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "CipherSuiteId: 0x0001 matches RFC 9420 §17.1's registry value" {
    try testing.expectEqual(@as(u16, 0x0001), @backingInt(CipherSuiteId.mls_128_dhkemx25519_aes128gcm_sha256_ed25519));
}

test "default suite: widths match RFC 9420 §17.1's MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 row" {
    // "128"-level suite: 128-bit AEAD key, 32-byte (256-bit) KDF/hash
    // output (HKDF-SHA256/SHA-256 always produce 32 bytes regardless of
    // the AEAD's own key size — this is normal, not a suite mismatch).
    try testing.expectEqual(@as(usize, 32), default.Nh);
    try testing.expectEqual(@as(usize, 16), default.Nk);
    try testing.expectEqual(@as(usize, 12), default.Nn);
    try testing.expectEqual(@as(usize, 64), default.Nx); // Ed25519: R(32) || S(32)
    try testing.expectEqual(@as(usize, 32), default.Nm); // HMAC-SHA256
    try testing.expectEqual(CipherSuiteId.mls_128_dhkemx25519_aes128gcm_sha256_ed25519, default.id);
}

test "0x0003: widths match RFC 9420 §17.1's MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 row" {
    const S = Mls128X25519ChaCha20Poly1305Sha256Ed25519;
    try testing.expectEqual(@as(u16, 0x0003), @backingInt(S.id));
    try testing.expectEqual(@as(usize, 32), S.Nh);
    try testing.expectEqual(@as(usize, 32), S.Nk); // ChaCha20: 256-bit key
    try testing.expectEqual(@as(usize, 12), S.Nn);
    try testing.expectEqual(@as(usize, 16), S.Aead.tag_length);
    try testing.expectEqual(@as(usize, 32), S.Nm);
}

test "default suite: hash() is plain SHA-256" {
    const got = default.hash("abc");
    // NIST SHA-256 KAT for the 3-byte message "abc".
    const want = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try testing.expectEqualSlices(u8, &want, &got);
}
