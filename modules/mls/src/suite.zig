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
const burn = @import("burn.zig");
const p256 = @import("p256");
const p384 = @import("p384");
const p521 = @import("p521");
const ed448 = @import("ed448").ed448;

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
        /// Whether `Sig` is an ECDSA scheme (std's / the `p256`/`p384`/
        /// `p521` siblings' `Ecdsa` surface, recognised by its DER codec)
        /// rather than EdDSA. Decides the two wire encodings RFC 9420
        /// §5.1.1/§5.1.2 make scheme-specific: public keys and signatures.
        pub const sig_is_ecdsa = @hasDecl(Sig_.Signature, "toDer");
        /// The signature scheme's MAXIMUM encoded-signature width in bytes
        /// (RFC 9420 §5.1.2 defers to the TLS 1.3 SignatureScheme
        /// encodings: EdDSA signatures are the fixed-width `R || S`, ECDSA
        /// signatures a DER `Ecdsa-Sig-Value`, whose length varies). Not
        /// named by the RFC; derived the way `Nh`/`Nk`/`Nn` are.
        pub const Nx = if (sig_is_ecdsa) Sig.Signature.der_encoded_length_max else Sig.Signature.encoded_length;
        /// The encoded signature PUBLIC key width (RFC 9420 §5.1.1: the
        /// raw RFC 8032 key for EdDSA, the UNCOMPRESSED SEC1 point for
        /// ECDSA).
        pub const Nspk = if (sig_is_ecdsa) Sig.PublicKey.uncompressed_sec1_encoded_length else Sig.PublicKey.encoded_length;
        /// The signature private key width as the interop vectors carry it:
        /// the RFC 8032 seed for EdDSA, the big-endian scalar for ECDSA.
        pub const Nssk = if (sig_is_ecdsa) Sig.SecretKey.encoded_length else Sig.KeyPair.seed_length;

        /// One encoded signature: `Nx` bytes of room, `len` of them used.
        pub const SignatureBytes = struct {
            buf: [Nx]u8,
            len: usize,

            pub fn slice(self: *const SignatureBytes) []const u8 {
                return self.buf[0..self.len];
            }
        };

        /// A signature in its RFC 9420 wire form (EdDSA `R || S`, ECDSA
        /// DER).
        pub fn encodeSignature(sig: Sig.Signature) SignatureBytes {
            var out: SignatureBytes = .{ .buf = undefined, .len = 0 };
            if (sig_is_ecdsa) {
                out.len = sig.toDer(&out.buf).len;
            } else {
                out.buf = sig.toBytes();
                out.len = Nx;
            }
            return out;
        }

        /// The inverse of `encodeSignature`. A signature of the wrong
        /// length (EdDSA) or that is not a DER `Ecdsa-Sig-Value` (ECDSA) is
        /// `error.WrongKeyLength` — the error every verifier in this
        /// module already returns for a signature it cannot even parse.
        pub fn decodeSignature(bytes: []const u8) error{WrongKeyLength}!Sig.Signature {
            if (sig_is_ecdsa) return Sig.Signature.fromDer(bytes) catch error.WrongKeyLength;
            if (bytes.len != Nx) return error.WrongKeyLength;
            return Sig.Signature.fromBytes(bytes[0..Nx].*);
        }

        /// A signature public key in its RFC 9420 §5.1.1 wire form.
        pub fn encodePublicKey(pk: Sig.PublicKey) [Nspk]u8 {
            return if (sig_is_ecdsa) pk.toUncompressedSec1() else pk.toBytes();
        }

        /// The inverse of `encodePublicKey`. A key of any other length is
        /// `error.WrongKeyLength`; for ECDSA that includes the COMPRESSED
        /// SEC1 form, which §5.1.1 does not allow ("the uncompressed
        /// Elliptic-Curve-Point-to-Octet-String conversion"). A
        /// right-length encoding that is not a valid key fails with the
        /// scheme's own error (not on the curve, non-canonical, identity).
        pub fn decodePublicKey(bytes: []const u8) !Sig.PublicKey {
            if (bytes.len != Nspk) return error.WrongKeyLength;
            if (sig_is_ecdsa) {
                if (bytes[0] != 0x04) return error.WrongKeyLength;
                return Sig.PublicKey.fromSec1(bytes);
            }
            return Sig.PublicKey.fromBytes(bytes[0..Nspk].*);
        }

        /// A signing key pair from its private key as the interop vectors
        /// encode it (`Nssk` bytes): the RFC 8032 seed for EdDSA, the
        /// scalar for ECDSA. Key in by pointer, pair out through `out`,
        /// the body under `burn.kem_burn` (the module's secret-API
        /// convention).
        pub fn signatureKeyPair(priv: *const [Nssk]u8, out: *Sig.KeyPair) @TypeOf(signatureKeyPairBody(priv, out)) {
            return burn.run(burn.kem_burn, @TypeOf(signatureKeyPairBody(priv, out)), signatureKeyPairBody, .{ priv, out });
        }

        fn signatureKeyPairBody(priv: *const [Nssk]u8, out: *Sig.KeyPair) !void {
            out.* = if (sig_is_ecdsa)
                try Sig.KeyPair.fromSecretKey(try Sig.SecretKey.fromBytes(priv.*))
            else
                try Sig.KeyPair.generateDeterministic(priv.*);
        }

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

/// `0x0002` = `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`: DHKEM(P-256,
/// HKDF-SHA256) + AES-128-GCM + SHA-256 + ECDSA over P-256 with SHA-256.
/// The KEM is `hpke.P256Kem` and the signature scheme the sibling `p256`
/// module's `EcdsaP256Sha256` (byte-exact to std's, constant-time signing,
/// several times faster). Public keys travel as uncompressed SEC1 points and
/// signatures as DER (RFC 9420 §5.1.1/§5.1.2), see `encodePublicKey`/
/// `encodeSignature`.
pub const Mls128P256Aes128GcmSha256P256 = CipherSuite(
    hpke.P256Kem,
    aesgcm.Aes128Gcm,
    std.crypto.kdf.hkdf.HkdfSha256,
    std.crypto.hash.sha2.Sha256,
    p256.EcdsaP256Sha256,
    .mls_128_dhkemp256_aes128gcm_sha256_p256,
);

/// `0x0005` = `MLS_256_DHKEMP521_AES256GCM_SHA512_P521`: DHKEM(P-521,
/// HKDF-SHA512) + AES-256-GCM + SHA-512 + ECDSA over P-521 with SHA-512, on
/// `hpke.P521Kem` and the sibling `p521` module (std has no P-521).
pub const Mls256P521Aes256GcmSha512P521 = CipherSuite(
    hpke.P521Kem,
    aesgcm.Aes256Gcm,
    std.crypto.kdf.hkdf.HkdfSha512,
    std.crypto.hash.sha2.Sha512,
    p521.EcdsaP521Sha512,
    .mls_256_dhkemp521_aes256gcm_sha512_p521,
);

/// `0x0007` = `MLS_256_DHKEMP384_AES256GCM_SHA384_P384`: DHKEM(P-384,
/// HKDF-SHA384) + AES-256-GCM + SHA-384 + ECDSA over P-384 with SHA-384, on
/// `hpke.P384Kem` and the sibling `p384` module.
pub const Mls256P384Aes256GcmSha384P384 = CipherSuite(
    hpke.P384Kem,
    aesgcm.Aes256Gcm,
    std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384),
    std.crypto.hash.sha2.Sha384,
    p384.EcdsaP384Sha384,
    .mls_256_dhkemp384_aes256gcm_sha384_p384,
);

/// RFC 8032 Ed448 (pure, empty context — RFC 9420 §5.1.2 names "Ed448" from
/// the TLS SignatureScheme registry, i.e. RFC 8032's PureEdDSA) in the
/// `std.crypto.sign.Ed25519` shape `CipherSuite` expects, over the sibling
/// `ed448` module (std has no Ed448). Keys and signatures travel raw
/// (57-byte public key, 114-byte `R || S`), as Ed25519's do.
pub const Ed448 = struct {
    pub const PublicKey = struct {
        bytes: [encoded_length]u8,

        pub const encoded_length = 57;

        /// Refuses an encoding that is not a point of the curve, as
        /// `std.crypto.sign.Ed25519.PublicKey.fromBytes` does.
        pub fn fromBytes(b: [encoded_length]u8) ed448.Point.DecodeError!PublicKey {
            _ = try ed448.Point.fromBytes(b);
            return .{ .bytes = b };
        }

        pub fn toBytes(pk: PublicKey) [encoded_length]u8 {
            return pk.bytes;
        }
    };

    pub const Signature = struct {
        bytes: [encoded_length]u8,

        pub const encoded_length = ed448.Signature.encoded_length; // 114

        /// The split is checked at `verify` (a non-canonical `S` fails
        /// verification there, RFC 8032 §5.2.7 step 1).
        pub fn fromBytes(b: [encoded_length]u8) Signature {
            return .{ .bytes = b };
        }

        pub fn toBytes(sig: Signature) [encoded_length]u8 {
            return sig.bytes;
        }

        pub fn verify(sig: Signature, msg: []const u8, pk: PublicKey) !void {
            const s = ed448.Signature.fromBytes(sig.bytes) catch return error.SignatureVerificationFailed;
            return ed448.verify(s, msg, "", ed448.PublicKey.fromBytes(pk.bytes));
        }
    };

    pub const KeyPair = struct {
        public_key: PublicKey,
        inner: ed448.KeyPair,

        pub const seed_length = 57;

        /// RFC 8032 §5.2.5 from a 57-byte seed. Error union for the
        /// `std.crypto.sign` shape; it never fails.
        pub fn generateDeterministic(seed: [seed_length]u8) error{}!KeyPair {
            var kp: KeyPair = undefined;
            generateDeterministicInto(&kp, &seed);
            return kp;
        }

        /// `generateDeterministic` with the seed by pointer and the key pair
        /// through `out` only (no copy in a caller's frame or result slot);
        /// `ed448.KeyPair.createInto` burns its own stack.
        pub fn generateDeterministicInto(out: *KeyPair, seed: *const [seed_length]u8) void {
            ed448.KeyPair.createInto(&out.inner, seed);
            out.public_key = .{ .bytes = out.inner.public_key.toBytes() };
        }

        /// Ed448 is deterministic; `noise` exists for the shape and is
        /// ignored.
        pub fn sign(kp: *const KeyPair, msg: []const u8, noise: ?[32]u8) ed448.SignError!Signature {
            _ = noise;
            const sig = try ed448.sign(&kp.inner, msg, "");
            return .{ .bytes = sig.toBytes() };
        }
    };
};

/// `0x0004` = `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`: DHKEM(X448,
/// HKDF-SHA512) + AES-256-GCM + SHA-512 + Ed448, on `hpke.X448Kem` and the
/// sibling `ed448` module.
pub const Mls256X448Aes256GcmSha512Ed448 = CipherSuite(
    hpke.X448Kem,
    aesgcm.Aes256Gcm,
    std.crypto.kdf.hkdf.HkdfSha512,
    std.crypto.hash.sha2.Sha512,
    Ed448,
    .mls_256_dhkemx448_aes256gcm_sha512_ed448,
);

/// `0x0006` = `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`: `0x0004`
/// with ChaCha20-Poly1305.
pub const Mls256X448ChaCha20Poly1305Sha512Ed448 = CipherSuite(
    hpke.X448Kem,
    hpke.ChaCha20Poly1305,
    std.crypto.kdf.hkdf.HkdfSha512,
    std.crypto.hash.sha2.Sha512,
    Ed448,
    .mls_256_dhkemx448_chacha20poly1305_sha512_ed448,
);

/// The suite a caller with no suite-negotiation needs of its own should
/// reach for first — RFC 9420 §16.1's mandatory-to-implement `0x0001`.
pub const default = Mls128X25519Aes128GcmSha256Ed25519;

/// Every suite this module instantiates, in registry order. The official
/// interop vectors are driven once per entry (`kat_*_test.zig`), so adding
/// a suite here is what puts it under every vector file.
pub const supported = .{
    Mls128X25519Aes128GcmSha256Ed25519,
    Mls128P256Aes128GcmSha256P256,
    Mls128X25519ChaCha20Poly1305Sha256Ed25519,
    Mls256X448Aes256GcmSha512Ed448,
    Mls256P521Aes256GcmSha512P521,
    Mls256X448ChaCha20Poly1305Sha512Ed448,
    Mls256P384Aes256GcmSha384P384,
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

test "0x0002: widths match RFC 9420 §17.1's MLS_128_DHKEMP256_AES128GCM_SHA256_P256 row" {
    const S = Mls128P256Aes128GcmSha256P256;
    try testing.expectEqual(@as(u16, 0x0002), @backingInt(S.id));
    try testing.expect(S.sig_is_ecdsa);
    try testing.expectEqual(@as(usize, 32), S.Nh);
    try testing.expectEqual(@as(usize, 16), S.Nk);
    try testing.expectEqual(@as(usize, 65), S.Nspk); // uncompressed SEC1
    try testing.expectEqual(@as(usize, 32), S.Nssk);
    try testing.expectEqual(@as(usize, 65), S.Kem.Npk);
}

test "0x0005: widths match RFC 9420 §17.1's MLS_256_DHKEMP521_AES256GCM_SHA512_P521 row" {
    const S5 = Mls256P521Aes256GcmSha512P521;
    try testing.expectEqual(@as(u16, 0x0005), @backingInt(S5.id));
    try testing.expectEqual(@as(usize, 64), S5.Nh);
    try testing.expectEqual(@as(usize, 32), S5.Nk);
    try testing.expectEqual(@as(usize, 64), S5.Nm);
    try testing.expectEqual(@as(usize, 133), S5.Nspk);
    try testing.expectEqual(@as(usize, 66), S5.Nssk);
}

test "0x0007: widths match RFC 9420 §17.1's MLS_256_DHKEMP384_AES256GCM_SHA384_P384 row" {
    const S7 = Mls256P384Aes256GcmSha384P384;
    try testing.expectEqual(@as(u16, 0x0007), @backingInt(S7.id));
    try testing.expectEqual(@as(usize, 48), S7.Nh);
    try testing.expectEqual(@as(usize, 32), S7.Nk);
    try testing.expectEqual(@as(usize, 48), S7.Nm);
    try testing.expectEqual(@as(usize, 97), S7.Nspk);
    try testing.expectEqual(@as(usize, 48), S7.Nssk);
}

test "0x0004/0x0006: widths match RFC 9420 §17.1's X448/Ed448 rows, and Ed448 signs and verifies" {
    inline for (.{ Mls256X448Aes256GcmSha512Ed448, Mls256X448ChaCha20Poly1305Sha512Ed448 }, .{ 0x0004, 0x0006 }) |S, id| {
        try testing.expectEqual(@as(u16, id), @backingInt(S.id));
        try testing.expect(!S.sig_is_ecdsa);
        try testing.expectEqual(@as(usize, 64), S.Nh);
        try testing.expectEqual(@as(usize, 32), S.Nk);
        try testing.expectEqual(@as(usize, 64), S.Nm);
        try testing.expectEqual(@as(usize, 114), S.Nx);
        try testing.expectEqual(@as(usize, 57), S.Nspk);
        try testing.expectEqual(@as(usize, 57), S.Nssk);
        try testing.expectEqual(@as(usize, 56), S.Kem.Npk);
    }
    const S = Mls256X448Aes256GcmSha512Ed448;
    // RFC 8032 §7.4 "-----blank" (Ed448, empty message, empty context).
    var seed: [57]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    var want_pk: [57]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_pk, "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
    var want_sig: [114]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_sig, "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
    var kp: S.Sig.KeyPair = undefined;
    try S.signatureKeyPair(&seed, &kp);
    try testing.expectEqualSlices(u8, &want_pk, &S.encodePublicKey(kp.public_key));
    const sig = S.encodeSignature(try kp.sign("", null));
    try testing.expectEqualSlices(u8, &want_sig, sig.slice());
    try (try S.decodeSignature(sig.slice())).verify("", try S.decodePublicKey(&want_pk));
    try testing.expectError(error.SignatureVerificationFailed, (try S.decodeSignature(sig.slice())).verify("x", kp.public_key));
    try testing.expectError(error.WrongKeyLength, S.decodeSignature(sig.slice()[0..113]));
}

test "ECDSA encodings: compressed keys and malformed DER are refused, a signature round-trips" {
    const S = Mls128P256Aes128GcmSha256P256;
    const kp = try S.Sig.KeyPair.generateDeterministic(@splat(0x11));
    const pk = S.encodePublicKey(kp.public_key);
    try testing.expectEqual(@as(u8, 0x04), pk[0]);
    _ = try S.decodePublicKey(&pk);
    // RFC 9420 §5.1.1: uncompressed only.
    const compressed = kp.public_key.toCompressedSec1();
    try testing.expectError(error.WrongKeyLength, S.decodePublicKey(&compressed));
    var bad_prefix = pk;
    bad_prefix[0] = 0x06; // hybrid form, same length
    try testing.expectError(error.WrongKeyLength, S.decodePublicKey(&bad_prefix));

    const sig = try kp.sign("msg", null);
    const der = S.encodeSignature(sig);
    try testing.expectEqual(@as(u8, 0x30), der.slice()[0]);
    const back = try S.decodeSignature(der.slice());
    try back.verify("msg", kp.public_key);
    try testing.expectError(error.WrongKeyLength, S.decodeSignature(der.slice()[0 .. der.len - 1]));
    try testing.expectError(error.WrongKeyLength, S.decodeSignature(&sig.toBytes())); // raw r||s is not DER
}

test "EdDSA encodings: a signature or key of the wrong length is WrongKeyLength" {
    const S = default;
    try testing.expect(!S.sig_is_ecdsa);
    const kp = try S.Sig.KeyPair.generateDeterministic(@splat(0x22));
    const pk = S.encodePublicKey(kp.public_key);
    try testing.expectError(error.WrongKeyLength, S.decodePublicKey(pk[0..31]));
    const sig = S.encodeSignature(try kp.sign("m", null));
    try testing.expectEqual(@as(usize, 64), sig.len);
    try testing.expectError(error.WrongKeyLength, S.decodeSignature(sig.slice()[0..63]));
    _ = try S.decodeSignature(sig.slice());
    var seed: [S.Nssk]u8 = @splat(0x22);
    var again: S.Sig.KeyPair = undefined;
    try S.signatureKeyPair(&seed, &again);
    try testing.expectEqualSlices(u8, &pk, &S.encodePublicKey(again.public_key));
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

test "mutation 2026-11-25: Ed448 PublicKey.fromBytes refuses a 57-byte string that is not a curve point" {
    const bad: [57]u8 = @splat(0xff);
    if (Ed448.PublicKey.fromBytes(bad)) |_| return error.TestUnexpectedResult else |_| {}
}
