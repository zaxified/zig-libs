// SPDX-License-Identifier: MIT

//! Key encodings: PKCS#8 (RFC 5958), SEC1 `ECPrivateKey` (RFC 5915), PKCS#1
//! (RFC 8017), SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) and their PEM armour
//! (RFC 7468), for EC (P-256, P-384, P-521, secp256k1), Ed25519/Ed448 and
//! X25519/X448 (RFC 8410), RSA and RSASSA-PSS, ML-DSA (RFC 9881) and ML-KEM
//! (RFC 9935).
//!
//! Type-agnostic: a parsed key is its algorithm plus slices of the input --
//! the EC scalar, the Ed/X key, the PKCS#1 DER, the ML seed and/or expanded
//! key, the public key where the encoding carries one. The step into a key
//! type (std's ECDSA, `p256`, `rsa`, ...) is the caller's, which keeps this
//! module free of every curve and signature dependency. What is checked
//! here: the DER (strict), the algorithm identifier, every length, an EC
//! scalar in [1, n). What is not: that a public point is on its curve, that
//! a stored public key belongs to the secret, that an ML `both` key's seed
//! expands to its expanded half, the RSA key's arithmetic. Those need the
//! arithmetic, so the key type checks them (SPEC § What this module is).
//!
//! Encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`, RFC 5958 §3 with PBES2, RFC
//! 8018): read and written with PBKDF2 (HMAC-SHA-1/224/256/384/512) or scrypt
//! and AES-128/192/256-CBC, the output of `openssl pkcs8 -topk8`
//! (`parseEncryptedPkcs8`, `parseEncryptedPrivateKeyPem`, `encryptPkcs8`,
//! `writeEncryptedPrivateKeyPem`; SPEC § Encrypted keys).
//!
//! Secrets: parsing copies nothing (the result points into the caller's DER,
//! which the caller wipes). The PEM paths decode and encode in constant time
//! (`b64ct`) and burn their stack.

const std = @import("std");
pub const der = @import("der.zig");
pub const pem = @import("pem.zig");
pub const pbes2 = @import("pbes2.zig");
const burn = @import("burn.zig");

pub const meta = .{
    .doc = "Key encodings: PKCS#8, SEC1, PKCS#1, SPKI and PEM for EC, Ed/X25519/448, RSA, ML-DSA, ML-KEM; type-agnostic, constant-time PEM",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Go crypto/x509 (ParsePKCS8PrivateKey, ParseECPrivateKey, ParsePKIXPublicKey, Marshal*) + encoding/pem; RustCrypto pkcs8/sec1/spki/pem-rfc7468",
    .deps = .{ "b64ct", "aescbc", "aes192" }, // aescbc/aes192: PBES2 encrypted PKCS#8
};

// ── algorithms ──────────────────────────────────────────────────────────────

pub const Algorithm = enum {
    ec_p256,
    ec_p384,
    ec_p521,
    ec_secp256k1,
    ed25519,
    ed448,
    x25519,
    x448,
    rsa,
    rsa_pss,
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    ml_kem_512,
    ml_kem_768,
    ml_kem_1024,

    pub fn isEc(a: Algorithm) bool {
        return switch (a) {
            .ec_p256, .ec_p384, .ec_p521, .ec_secp256k1 => true,
            else => false,
        };
    }

    pub fn isRsa(a: Algorithm) bool {
        return a == .rsa or a == .rsa_pss;
    }

    /// ML-DSA or ML-KEM: a private key with a seed and an expanded form.
    pub fn isPq(a: Algorithm) bool {
        return switch (a) {
            .ml_dsa_44, .ml_dsa_65, .ml_dsa_87, .ml_kem_512, .ml_kem_768, .ml_kem_1024 => true,
            else => false,
        };
    }

    /// EC: the order's length (an RFC 5915 scalar's length); Ed/X: the raw
    /// private key; ML: the seed. Null for RSA.
    pub fn secretLen(a: Algorithm) ?usize {
        return switch (a) {
            .ec_p256, .ec_secp256k1, .ed25519, .x25519, .ml_dsa_44, .ml_dsa_65, .ml_dsa_87 => 32,
            .ec_p384 => 48,
            .ec_p521 => 66,
            .ed448 => 57,
            .x448 => 56,
            .ml_kem_512, .ml_kem_768, .ml_kem_1024 => 64,
            .rsa, .rsa_pss => null,
        };
    }

    /// ML: the expanded private key's length (FIPS 204 sk, FIPS 203 dk).
    pub fn expandedLen(a: Algorithm) ?usize {
        return switch (a) {
            .ml_dsa_44 => 2560,
            .ml_dsa_65 => 4032,
            .ml_dsa_87 => 4896,
            .ml_kem_512 => 1632,
            .ml_kem_768 => 2400,
            .ml_kem_1024 => 3168,
            else => null,
        };
    }

    /// Ed/X/ML: the public key's length. EC: the uncompressed point's
    /// (a compressed one is `secretLen + 1`). Null for RSA.
    pub fn publicLen(a: Algorithm) ?usize {
        return switch (a) {
            .ec_p256, .ec_secp256k1 => 65,
            .ec_p384 => 97,
            .ec_p521 => 133,
            .ed25519, .x25519 => 32,
            .ed448 => 57,
            .x448 => 56,
            .ml_dsa_44 => 1312,
            .ml_dsa_65 => 1952,
            .ml_dsa_87 => 2592,
            .ml_kem_512 => 800,
            .ml_kem_768 => 1184,
            .ml_kem_1024 => 1568,
            .rsa, .rsa_pss => null,
        };
    }

    /// The AlgorithmIdentifier's OID; for EC the named curve's (the key
    /// OID is `oid.ec_public_key`).
    pub fn oidBytes(a: Algorithm) []const u8 {
        return switch (a) {
            .ec_p256 => &oid.prime256v1,
            .ec_p384 => &oid.secp384r1,
            .ec_p521 => &oid.secp521r1,
            .ec_secp256k1 => &oid.secp256k1,
            .ed25519 => &oid.ed25519,
            .ed448 => &oid.ed448,
            .x25519 => &oid.x25519,
            .x448 => &oid.x448,
            .rsa => &oid.rsa_encryption,
            .rsa_pss => &oid.rsassa_pss,
            .ml_dsa_44 => &oid.ml_dsa_44,
            .ml_dsa_65 => &oid.ml_dsa_65,
            .ml_dsa_87 => &oid.ml_dsa_87,
            .ml_kem_512 => &oid.ml_kem_512,
            .ml_kem_768 => &oid.ml_kem_768,
            .ml_kem_1024 => &oid.ml_kem_1024,
        };
    }

    fn fromCurveOid(o: []const u8) ?Algorithm {
        inline for (.{ .ec_p256, .ec_p384, .ec_p521, .ec_secp256k1 }) |a| {
            if (std.mem.eql(u8, o, (comptime @as(Algorithm, a)).oidBytes())) return a;
        }
        return null;
    }

    fn fromKeyOid(o: []const u8) ?Algorithm {
        inline for (.{ .ed25519, .ed448, .x25519, .x448, .rsa, .rsa_pss, .ml_dsa_44, .ml_dsa_65, .ml_dsa_87, .ml_kem_512, .ml_kem_768, .ml_kem_1024 }) |a| {
            if (std.mem.eql(u8, o, (comptime @as(Algorithm, a)).oidBytes())) return a;
        }
        return null;
    }

    /// Big-endian group order n of an EC algorithm (the bound on its
    /// scalars); null for a non-EC algorithm.
    pub fn order(a: Algorithm) ?[]const u8 {
        return switch (a) {
            .ec_p256 => &order_p256,
            .ec_p384 => &order_p384,
            .ec_p521 => &order_p521,
            .ec_secp256k1 => &order_secp256k1,
            else => null,
        };
    }
};

/// The OIDs, content octets only.
pub const oid = struct {
    pub const ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
    pub const prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
    pub const secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 }; // 1.3.132.0.34
    pub const secp521r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x23 }; // 1.3.132.0.35
    pub const secp256k1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x0a }; // 1.3.132.0.10
    pub const x25519 = [_]u8{ 0x2b, 0x65, 0x6e }; // 1.3.101.110
    pub const x448 = [_]u8{ 0x2b, 0x65, 0x6f }; // 1.3.101.111
    pub const ed25519 = [_]u8{ 0x2b, 0x65, 0x70 }; // 1.3.101.112
    pub const ed448 = [_]u8{ 0x2b, 0x65, 0x71 }; // 1.3.101.113
    pub const rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }; // 1.2.840.113549.1.1.1
    pub const rsassa_pss = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a }; // 1.2.840.113549.1.1.10
    pub const ml_dsa_44 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 }; // 2.16.840.1.101.3.4.3.17
    pub const ml_dsa_65 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 }; // 2.16.840.1.101.3.4.3.18
    pub const ml_dsa_87 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 }; // 2.16.840.1.101.3.4.3.19
    pub const ml_kem_512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01 }; // 2.16.840.1.101.3.4.4.1
    pub const ml_kem_768 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02 }; // 2.16.840.1.101.3.4.4.2
    pub const ml_kem_1024 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03 }; // 2.16.840.1.101.3.4.4.3
};

fn beBytes(comptime T: type, comptime v: anytype) [@divExact(@bitSizeOf(T), 8)]u8 {
    var b: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .big);
    return b;
}

const order_p256 = beBytes(u256, std.crypto.ecc.P256.scalar.field_order);
const order_p384 = beBytes(u384, std.crypto.ecc.P384.scalar.field_order);
const order_secp256k1 = beBytes(u256, std.crypto.ecc.Secp256k1.scalar.field_order);
// std has no P-521; FIPS 186-5 / SEC 2 n (the `p521` module's
// `scalar.field_order`, pinned by a test).
const order_p521 = beBytes(u528, 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409);

// ── errors and limits ───────────────────────────────────────────────────────

/// A structure this module cannot read: bad DER, a wrong version, a length
/// that does not fit the algorithm, an EC scalar out of [1, n), parameters
/// where the RFC forbids them, a curve named twice and differently.
pub const ParseError = error{
    MalformedKey,
    /// Well-formed, but an algorithm or curve outside `Algorithm` (DSA,
    /// brainpool, explicit EC parameters, SLH-DSA, ...).
    UnsupportedAlgorithm,
};

pub const PemError = ParseError || error{
    InvalidPem,
    /// No key block (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`; for
    /// public keys `PUBLIC KEY`, `RSA PUBLIC KEY`) in the text.
    MissingKey,
    /// `ENCRYPTED PRIVATE KEY` (PKCS#8 PBES2) or a legacy `Proc-Type:
    /// 4,ENCRYPTED` block: `parsePrivateKeyPem` has no password to read it
    /// with. The first is `parseEncryptedPrivateKeyPem`'s; the second is not
    /// read at all (SPEC § Encrypted keys).
    EncryptedKey,
    /// An `OPENSSH PRIVATE KEY` block: the `ssh` module reads those.
    UnsupportedFormat,
    /// `der_buf` is shorter than the key's DER (`max_private_der_len` fits
    /// every key this module accepts).
    NoSpaceLeft,
};

pub const WriteError = error{
    /// The key's fields do not fit its algorithm (a length, a missing part).
    MalformedKey,
    NoSpaceLeft,
};

/// `parseEncryptedPkcs8`: `pbes2.DecryptError` (a structure that is not
/// PBES2 / PBKDF2-or-scrypt / AES-CBC is `UnsupportedEncryption`; a file
/// asking more of the key derivation than `DecryptOptions` allows is
/// `KdfParamsTooLarge`; a wrong password is `IncorrectPasswordOrCorrupt`) and
/// the decrypted key's own refusal.
pub const EncryptedKeyError = pbes2.DecryptError || error{
    /// The password was right (the plaintext is a well-formed PKCS#8) but the
    /// key's algorithm is outside `Algorithm`.
    UnsupportedAlgorithm,
};

pub const EncryptedPemError = EncryptedKeyError || error{
    InvalidPem,
    /// No `ENCRYPTED PRIVATE KEY` block, and no private-key block at all.
    MissingKey,
    /// The first private-key block is not encrypted (`PRIVATE KEY`, `EC
    /// PRIVATE KEY`, `RSA PRIVATE KEY`): `parsePrivateKeyPem` reads it.
    NotEncrypted,
    /// An `OPENSSH PRIVATE KEY` block: the `ssh` module reads those.
    UnsupportedFormat,
};

/// `encryptPkcs8` / `writeEncryptedPrivateKeyPem`: `InvalidOptions` for an
/// option outside its range (iterations, scrypt cost or work buffer, salt
/// length), `MalformedKey` for a key that does not fit its algorithm.
pub const EncryptWriteError = pbes2.EncryptError;

/// A DER buffer of this size holds any private key this module parses or
/// writes: RSA up to 16384 bits (~9.4 KiB PKCS#8), ML-DSA-87 `both` (~5 KiB).
pub const max_private_der_len = 16 * 1024;

/// `max_private_der_len` for SubjectPublicKeyInfo (RSA 16384-bit ~2.1 KiB,
/// ML-DSA-87 ~2.6 KiB).
pub const max_public_der_len = 4 * 1024;

/// PEM text of a `max_private_der_len` key, as `writePrivateKeyPem` writes it.
pub const max_private_pem_len = pem.encodedLen("ENCRYPTED PRIVATE KEY", max_private_der_len);

// ── private keys ────────────────────────────────────────────────────────────

/// Which structure a private key came in (and `writePrivateKeyDer` writes).
pub const Encoding = enum {
    /// PrivateKeyInfo / OneAsymmetricKey (RFC 5958), PEM `PRIVATE KEY`.
    pkcs8,
    /// ECPrivateKey (RFC 5915), PEM `EC PRIVATE KEY`. EC only.
    sec1,
    /// RSAPrivateKey (RFC 8017 A.1.2), PEM `RSA PRIVATE KEY`. RSA only.
    pkcs1,

    pub fn pemLabel(e: Encoding) []const u8 {
        return switch (e) {
            .pkcs8 => "PRIVATE KEY",
            .sec1 => "EC PRIVATE KEY",
            .pkcs1 => "RSA PRIVATE KEY",
        };
    }
};

/// The ML-DSA / ML-KEM private-key CHOICE (RFC 9881 §6, RFC 9935 §6).
pub const PqForm = enum {
    /// `seed [0] IMPLICIT OCTET STRING`: the 32- or 64-byte seed only.
    seed,
    /// `expandedKey OCTET STRING`: the FIPS 204 sk / FIPS 203 dk only.
    expanded,
    /// `both SEQUENCE { seed, expandedKey }` (OpenSSL 3.5's default).
    both,
};

/// A private key as its parts, each a slice of the parsed DER (or, to
/// write one, of the caller's own buffers).
pub const PrivateKey = struct {
    algorithm: Algorithm,
    encoding: Encoding,
    /// EC: the RFC 5915 scalar as encoded, 1..`secretLen` octets (a shorter
    /// one has had leading zeros dropped; `scalarInto` pads it), in [1, n).
    /// Ed/X: the raw private key. RSA: the whole RSAPrivateKey (PKCS#1)
    /// DER, for the `rsa` module. ML: the seed (`.seed`, `.both`) or the
    /// expanded key (`.expanded`).
    secret: []const u8,
    /// ML `.both`: the expanded key; empty otherwise.
    expanded: []const u8 = &.{},
    /// ML only.
    pq_form: ?PqForm = null,
    /// The public key the encoding carries, as stored and NOT checked
    /// against `secret`: EC: the SEC1 point of RFC 5915's `[1] publicKey`
    /// (shape checked, not on-curve); PKCS#8 v2 `[1] publicKey` otherwise.
    public: ?[]const u8 = null,
    /// RSASSA-PSS: the AlgorithmIdentifier's parameters (a whole
    /// `RSASSA-PSS-params` SEQUENCE TLV), empty when absent.
    parameters: []const u8 = &.{},

    /// The EC scalar left-padded into `out`, which must be exactly
    /// `secretLen` long. Writes nothing and returns `MalformedKey` for a
    /// non-EC key or a wrong `out` length. `out` then holds the secret.
    pub fn scalarInto(k: *const PrivateKey, out: []u8) error{MalformedKey}!void {
        if (!k.algorithm.isEc()) return error.MalformedKey;
        const n = k.algorithm.secretLen().?;
        if (out.len != n or k.secret.len == 0 or k.secret.len > n) return error.MalformedKey;
        @memset(out[0 .. n - k.secret.len], 0);
        @memcpy(out[n - k.secret.len ..], k.secret);
    }
};

/// A PKCS#8 PrivateKeyInfo (v1) or OneAsymmetricKey (v2): `attributes [0]`
/// are skipped, `publicKey [1]` (v2 only) goes to `public`.
pub fn parsePkcs8(bytes: []const u8) ParseError!PrivateKey {
    var top = der.Reader.init(bytes);
    var info = try top.sub(0x30);
    try top.end();
    const version = try info.smallInt();
    if (version > 1) return error.MalformedKey;
    var alg = try info.sub(0x30);
    const key_oid = try alg.expect(0x06);
    const private = try info.expect(0x04);
    if (info.peekTag() == 0xa0) try checkAttributes(try info.expect(0xa0));
    var public_v2: ?[]const u8 = null;
    if (info.peekTag() == 0x81) {
        if (version != 1) return error.MalformedKey; // RFC 5958: publicKey only in v2
        public_v2 = try bitStringBytes(try info.expect(0x81));
    }
    try info.end();

    if (std.mem.eql(u8, key_oid, &oid.ec_public_key)) {
        // RFC 5480 §2.1.1: namedCurve (no specifiedCurve -- RFC 5480 forbids
        // it in PKIX, Go refuses it). Absent parameters fall back to the
        // inner ECPrivateKey's `[0]`, as Go's `ParsePKCS8PrivateKey` does.
        var curve: ?Algorithm = null;
        if (!alg.atEnd()) {
            if (alg.peekTag() != 0x06) return error.UnsupportedAlgorithm;
            curve = Algorithm.fromCurveOid(try alg.expect(0x06)) orelse return error.UnsupportedAlgorithm;
            try alg.end();
        }
        var k = try parseEcInner(private, curve);
        k.encoding = .pkcs8;
        if (public_v2) |p| {
            if (k.public != null) return error.MalformedKey; // two public keys
            try checkPoint(k.algorithm, p);
            k.public = p;
        }
        return k;
    }
    const a = Algorithm.fromKeyOid(key_oid) orelse return error.UnsupportedAlgorithm;
    var k: PrivateKey = .{ .algorithm = a, .encoding = .pkcs8, .secret = &.{} };
    switch (a) {
        .rsa => {
            try nullOrAbsentParams(&alg);
            try checkPkcs1Private(private);
            k.secret = private;
        },
        .rsa_pss => {
            k.parameters = try pssParams(&alg);
            try checkPkcs1Private(private);
            k.secret = private;
        },
        .ed25519, .ed448, .x25519, .x448 => {
            try alg.end(); // RFC 8410 §3: parameters MUST be absent
            // CurvePrivateKey ::= OCTET STRING
            var inner = der.Reader.init(private);
            const raw = try inner.expect(0x04);
            try inner.end();
            if (raw.len != a.secretLen().?) return error.MalformedKey;
            k.secret = raw;
            if (public_v2) |p| if (p.len != a.publicLen().?) return error.MalformedKey;
        },
        .ec_p256, .ec_p384, .ec_p521, .ec_secp256k1 => unreachable, // `fromKeyOid` yields none
        .ml_dsa_44, .ml_dsa_65, .ml_dsa_87, .ml_kem_512, .ml_kem_768, .ml_kem_1024 => {
            try alg.end(); // RFC 9881 §2, RFC 9935 §2: parameters MUST be absent
            try parsePq(&k, private);
            if (public_v2) |p| if (p.len != a.publicLen().?) return error.MalformedKey;
        },
    }
    if (public_v2) |p| if (a.isRsa()) try checkPkcs1Public(p);
    k.public = public_v2;
    return k;
}

/// A SEC1 / RFC 5915 ECPrivateKey (`openssl ec` output). `curve` is the curve
/// the context already names (null for a bare key, which then needs its
/// `[0] parameters`); a `[0]` naming another curve is `MalformedKey`.
pub fn parseSec1(bytes: []const u8, curve: ?Algorithm) ParseError!PrivateKey {
    if (curve) |c| if (!c.isEc()) return error.MalformedKey;
    var k = try parseEcInner(bytes, curve);
    k.encoding = .sec1;
    return k;
}

fn parseEcInner(bytes: []const u8, known: ?Algorithm) ParseError!PrivateKey {
    var top = der.Reader.init(bytes);
    var key = try top.sub(0x30);
    try top.end();
    if (try key.smallInt() != 1) return error.MalformedKey; // ecPrivkeyVer1
    const raw = try key.expect(0x04);
    var curve = known;
    if (key.peekTag() == 0xa0) {
        var params = try key.sub(0xa0);
        if (params.peekTag() != 0x06) return error.UnsupportedAlgorithm; // explicit parameters
        const c = Algorithm.fromCurveOid(try params.expect(0x06)) orelse return error.UnsupportedAlgorithm;
        try params.end();
        if (curve) |k| if (k != c) return error.MalformedKey;
        curve = c;
    }
    const alg = curve orelse return error.MalformedKey;
    var public: ?[]const u8 = null;
    if (key.peekTag() == 0xa1) {
        var p = try key.sub(0xa1);
        const point = try bitStringBytes(try p.expect(0x03));
        try p.end();
        try checkPoint(alg, point);
        public = point;
    }
    try key.end();
    if (raw.len == 0 or raw.len > alg.secretLen().?) return error.MalformedKey;
    if (!scalarInRange(raw, alg.order().?)) return error.MalformedKey;
    return .{ .algorithm = alg, .encoding = .sec1, .secret = raw, .public = public };
}

/// An RSAPrivateKey (PKCS#1) DER: its outer shape only (SEQUENCE of a
/// version 0 or 1 and INTEGERs); the `rsa` module reads the numbers.
pub fn parsePkcs1(bytes: []const u8) ParseError!PrivateKey {
    try checkPkcs1Private(bytes);
    return .{ .algorithm = .rsa, .encoding = .pkcs1, .secret = bytes };
}

/// Any of the three private-key DERs, told apart by their structure:
/// PKCS#8 (`version`, then a SEQUENCE), SEC1 (`1`, then an OCTET STRING),
/// PKCS#1 (`0`/`1`, then an INTEGER) -- what Go's
/// `ParsePKCS8PrivateKey`/`ParseECPrivateKey`/`ParsePKCS1PrivateKey` trio
/// leaves to the caller.
pub fn parsePrivateKeyDer(bytes: []const u8) ParseError!PrivateKey {
    var top = der.Reader.init(bytes);
    var s = try top.sub(0x30);
    _ = try s.smallInt();
    return switch (s.peekTag() orelse return error.MalformedKey) {
        0x30 => parsePkcs8(bytes),
        0x04 => parseSec1(bytes, null),
        0x02 => parsePkcs1(bytes),
        else => error.MalformedKey,
    };
}

/// The first private-key block of `text` (`PRIVATE KEY`, `EC PRIVATE KEY`,
/// `RSA PRIVATE KEY`; other blocks, such as `EC PARAMETERS` or a
/// certificate chain, are skipped), decoded into `der_buf` in constant time
/// and parsed. Only the first key block counts: its error is the result even
/// when a good key follows, and an `ENCRYPTED PRIVATE KEY` or `OPENSSH
/// PRIVATE KEY` block before any plain key is `EncryptedKey` /
/// `UnsupportedFormat` -- a file meant to hold one key that holds another
/// first is the caller's to see, not something to paper over. The result points into `der_buf`: the caller wipes it
/// (`std.crypto.secureZero`) when done, also after an error (the decoded
/// part is wiped here on a parse error, but not past the decoded length).
pub fn parsePrivateKeyPem(text: []const u8, der_buf: []u8) PemError!PrivateKey {
    return burn.run(burn.pem_burn, PemError!PrivateKey, parsePrivateKeyPemBody, .{ text, der_buf });
}

fn parsePrivateKeyPemBody(text: []const u8, der_buf: []u8) PemError!PrivateKey {
    var it: pem.Iterator = .init(text);
    while (try it.next()) |b| {
        const encoding: Encoding = if (std.mem.eql(u8, b.label, "PRIVATE KEY"))
            .pkcs8
        else if (std.mem.eql(u8, b.label, "EC PRIVATE KEY"))
            .sec1
        else if (std.mem.eql(u8, b.label, "RSA PRIVATE KEY"))
            .pkcs1
        else if (std.mem.eql(u8, b.label, "ENCRYPTED PRIVATE KEY"))
            return error.EncryptedKey
        else if (std.mem.eql(u8, b.label, "OPENSSH PRIVATE KEY"))
            return error.UnsupportedFormat
        else
            continue;
        if (b.isEncrypted()) return error.EncryptedKey;
        const bytes = try b.decode(der_buf);
        errdefer std.crypto.secureZero(u8, der_buf[0..bytes.len]);
        return switch (encoding) {
            .pkcs8 => try parsePkcs8(bytes),
            .sec1 => try parseSec1(bytes, null),
            .pkcs1 => try parsePkcs1(bytes),
        };
    }
    return error.MissingKey;
}

// ── encrypted private keys ──────────────────────────────────────────────────

pub const DecryptOptions = pbes2.DecryptOptions;
pub const EncryptOptions = pbes2.EncryptOptions;

/// The structure of an `EncryptedPrivateKeyInfo` (the KDF and its
/// parameters, the salt, the cipher, the IV, the ciphertext) without any
/// decryption: what a caller reads to choose its `DecryptOptions`, or to
/// show "scrypt, AES-256-CBC" before asking for a password.
pub const parseEncryptedInfo = pbes2.parse;

/// A DER buffer of this size holds any `EncryptedPrivateKeyInfo` that
/// `encryptPkcs8` writes (a `max_private_der_len` key padded to a block, plus
/// the algorithm parameters).
pub const max_encrypted_der_len = max_private_der_len + 16 + pbes2.max_overhead;

/// PEM text of a `max_encrypted_der_len` block.
pub const max_encrypted_pem_len = pem.encodedLen("ENCRYPTED PRIVATE KEY", max_encrypted_der_len);

/// Decrypt a DER `EncryptedPrivateKeyInfo` into `out` (at least as long as
/// its ciphertext, which is no longer than the file) and return the PKCS#8
/// `PrivateKeyInfo` it held, `out[0..n]`. The caller wipes `out`
/// (`std.crypto.secureZero`) when done; on an error everything written to it
/// is already wiped. See `pbes2.decrypt` for the padding and wiping
/// contract. `parseEncryptedPkcs8` is this plus `parsePkcs8`.
pub fn decryptPkcs8(bytes: []const u8, password: []const u8, out: []u8, opts: DecryptOptions) pbes2.DecryptError![]u8 {
    return burn.run(burn.pbes2_burn, pbes2.DecryptError![]u8, decryptPkcs8Body, .{ bytes, password, out, opts });
}

fn decryptPkcs8Body(bytes: []const u8, password: []const u8, out: []u8, opts: DecryptOptions) pbes2.DecryptError![]u8 {
    const info = try pbes2.parse(bytes);
    return pbes2.decrypt(info, password, out, opts);
}

/// A PKCS#8 `EncryptedPrivateKeyInfo` (PBES2) decrypted into `out` and
/// parsed: the key's parts point into `out`, which the caller wipes. A wrong
/// password, a damaged ciphertext and a plaintext that is not a PKCS#8
/// structure are all `IncorrectPasswordOrCorrupt`; a well-formed plaintext
/// with an algorithm outside `Algorithm` is `UnsupportedAlgorithm`.
pub fn parseEncryptedPkcs8(bytes: []const u8, password: []const u8, out: []u8, opts: DecryptOptions) EncryptedKeyError!PrivateKey {
    return burn.run(burn.pbes2_burn, EncryptedKeyError!PrivateKey, parseEncryptedPkcs8Body, .{ bytes, password, out, opts });
}

fn parseEncryptedPkcs8Body(bytes: []const u8, password: []const u8, out: []u8, opts: DecryptOptions) EncryptedKeyError!PrivateKey {
    const info = try pbes2.parse(bytes);
    return parseDecrypted(info, password, out, opts);
}

fn parseDecrypted(info: pbes2.Info, password: []const u8, out: []u8, opts: DecryptOptions) EncryptedKeyError!PrivateKey {
    const plain = try pbes2.decrypt(info, password, out, opts);
    return parsePkcs8(plain) catch |err| {
        std.crypto.secureZero(u8, plain);
        return switch (err) {
            error.MalformedKey => error.IncorrectPasswordOrCorrupt,
            error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
        };
    };
}

/// The first `ENCRYPTED PRIVATE KEY` block of `text`, decoded into `der_buf`,
/// decrypted in place there and parsed: the key's parts point into
/// `der_buf`, which the caller wipes (also after an error: what held
/// plaintext is wiped here, the rest was ciphertext). Blocks that are not
/// private keys (`EC PARAMETERS`, certificates) are skipped; a plain private
/// key block first is `NotEncrypted` (`parsePrivateKeyPem` reads that), a
/// legacy `Proc-Type: 4,ENCRYPTED` block `UnsupportedEncryption` (SPEC §
/// Encrypted keys: not read), an `OPENSSH PRIVATE KEY` block
/// `UnsupportedFormat`.
pub fn parseEncryptedPrivateKeyPem(text: []const u8, password: []const u8, der_buf: []u8, opts: DecryptOptions) EncryptedPemError!PrivateKey {
    return burn.run(burn.pbes2_burn + burn.pem_burn, EncryptedPemError!PrivateKey, parseEncryptedPrivateKeyPemBody, .{ text, password, der_buf, opts });
}

fn parseEncryptedPrivateKeyPemBody(text: []const u8, password: []const u8, der_buf: []u8, opts: DecryptOptions) EncryptedPemError!PrivateKey {
    var it: pem.Iterator = .init(text);
    while (try it.next()) |b| {
        if (std.mem.eql(u8, b.label, "ENCRYPTED PRIVATE KEY")) {
            if (b.isEncrypted()) return error.UnsupportedEncryption;
            const bytes = try b.decode(der_buf);
            const info = try pbes2.parse(bytes);
            // Decrypt over the ciphertext itself (CBC reads each block before
            // it writes it): one buffer, no second copy of the key.
            const ct_at = @intFromPtr(info.ciphertext.ptr) - @intFromPtr(der_buf.ptr);
            return parseDecrypted(info, password, der_buf[ct_at..][0..info.ciphertext.len], opts);
        }
        if (std.mem.eql(u8, b.label, "OPENSSH PRIVATE KEY")) return error.UnsupportedFormat;
        if (std.mem.eql(u8, b.label, "PRIVATE KEY") or std.mem.eql(u8, b.label, "EC PRIVATE KEY") or
            std.mem.eql(u8, b.label, "RSA PRIVATE KEY")) return error.NotEncrypted;
    }
    return error.MissingKey;
}

/// `k` as a PKCS#8 `EncryptedPrivateKeyInfo` under PBES2 into `out`
/// (`encryptedLen`-sized, `max_encrypted_der_len` fits every key): the key is
/// written as PKCS#8 whatever `k.encoding` says, as `openssl pkcs8 -topk8`
/// does. Salt and IV come from `random` -- a CSPRNG for a real key file.
/// `EncryptOptions{}` is `openssl pkcs8 -topk8`'s default output shape.
/// The plaintext exists only in a wiped stack buffer; `out` is wiped on
/// every error.
pub fn encryptPkcs8(out: []u8, k: PrivateKey, password: []const u8, random: std.Random, opts: EncryptOptions) EncryptWriteError![]u8 {
    return burn.run(burn.pbes2_write_burn, EncryptWriteError![]u8, encryptPkcs8Body, .{ out, k, password, random, opts });
}

fn encryptPkcs8Body(out: []u8, k: PrivateKey, password: []const u8, random: std.Random, opts: EncryptOptions) EncryptWriteError![]u8 {
    var stage: [max_private_der_len + 16]u8 = undefined;
    defer std.crypto.secureZero(u8, &stage);
    const plain = writePkcs8(stage[0..max_private_der_len], k) catch |err| return switch (err) {
        error.NoSpaceLeft => error.MalformedKey, // larger than any key `checkWritable` admits
        error.MalformedKey => error.MalformedKey,
    };
    return pbes2.encrypt(out, &stage, plain.len, password, random, opts);
}

/// `encryptPkcs8` armoured as PEM `ENCRYPTED PRIVATE KEY` (64-column lines,
/// LF: `openssl pkcs8 -topk8`'s text).
pub fn writeEncryptedPrivateKeyPem(out: []u8, k: PrivateKey, password: []const u8, random: std.Random, opts: EncryptOptions) EncryptWriteError![]u8 {
    var buf: [max_encrypted_der_len]u8 = undefined; // ciphertext: public
    const bytes = encryptPkcs8(&buf, k, password, random, opts) catch |err| return switch (err) {
        error.NoSpaceLeft => error.MalformedKey, // larger than any key `checkWritable` admits
        else => err,
    };
    return pem.encode(out, "ENCRYPTED PRIVATE KEY", bytes) catch |err| switch (err) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        error.InvalidPem => unreachable, // fixed, valid label
    };
}

// ── public keys ─────────────────────────────────────────────────────────────

pub const PublicKey = struct {
    algorithm: Algorithm,
    /// EC: the SEC1 point (uncompressed or compressed; shape checked, not
    /// on-curve). Ed/X/ML: the raw key. RSA: the RSAPublicKey (PKCS#1) DER.
    key: []const u8,
    /// RSASSA-PSS: the parameters SEQUENCE TLV, empty when absent.
    parameters: []const u8 = &.{},
};

/// A SubjectPublicKeyInfo (`openssl pkey -pubout`, the key inside a
/// certificate).
pub fn parseSpki(bytes: []const u8) ParseError!PublicKey {
    var top = der.Reader.init(bytes);
    var spki = try top.sub(0x30);
    try top.end();
    var alg = try spki.sub(0x30);
    const key_oid = try alg.expect(0x06);
    const key = try bitStringBytes(try spki.expect(0x03));
    try spki.end();

    if (std.mem.eql(u8, key_oid, &oid.ec_public_key)) {
        if (alg.peekTag() != 0x06) return error.UnsupportedAlgorithm;
        const curve = Algorithm.fromCurveOid(try alg.expect(0x06)) orelse return error.UnsupportedAlgorithm;
        try alg.end();
        try checkPoint(curve, key);
        return .{ .algorithm = curve, .key = key };
    }
    const a = Algorithm.fromKeyOid(key_oid) orelse return error.UnsupportedAlgorithm;
    var pk: PublicKey = .{ .algorithm = a, .key = key };
    switch (a) {
        .rsa => {
            try nullOrAbsentParams(&alg);
            try checkPkcs1Public(key);
        },
        .rsa_pss => {
            pk.parameters = try pssParams(&alg);
            try checkPkcs1Public(key);
        },
        else => {
            try alg.end();
            if (key.len != a.publicLen().?) return error.MalformedKey;
        },
    }
    return pk;
}

/// An RSAPublicKey (PKCS#1) DER: SEQUENCE { modulus, publicExponent }.
pub fn parsePkcs1Public(bytes: []const u8) ParseError!PublicKey {
    try checkPkcs1Public(bytes);
    return .{ .algorithm = .rsa, .key = bytes };
}

/// The first `PUBLIC KEY` (SPKI) or `RSA PUBLIC KEY` (PKCS#1) block of
/// `text`, decoded into `der_buf`. A certificate is not a public key here:
/// `x509.spkiOf` reads one.
pub fn parsePublicKeyPem(text: []const u8, der_buf: []u8) PemError!PublicKey {
    var it: pem.Iterator = .init(text);
    while (try it.next()) |b| {
        const spki = std.mem.eql(u8, b.label, "PUBLIC KEY");
        if (!spki and !std.mem.eql(u8, b.label, "RSA PUBLIC KEY")) continue;
        const bytes = try b.decode(der_buf);
        return if (spki) try parseSpki(bytes) else try parsePkcs1Public(bytes);
    }
    return error.MissingKey;
}

// ── writers ─────────────────────────────────────────────────────────────────

/// `k` as PKCS#8 into `out`. v1 (PrivateKeyInfo) unless `k.public` is set
/// for a non-EC key, then v2 with `[1] publicKey` (an EC public key rides in
/// the inner ECPrivateKey, as OpenSSL writes it). Byte-identical to
/// `openssl pkey`'s output for every form in `src/vectors.zig`.
pub fn writePkcs8(out: []u8, k: PrivateKey) WriteError![]u8 {
    try checkWritable(k);
    var w = der.Writer.init(out);
    const a = k.algorithm;
    const v2 = !a.isEc() and k.public != null;

    const alg_len = switch (a) {
        .ec_p256, .ec_p384, .ec_p521, .ec_secp256k1 => der.tlvLen(oid.ec_public_key.len) + der.tlvLen(a.oidBytes().len),
        .rsa => der.tlvLen(a.oidBytes().len) + der.tlvLen(0),
        .rsa_pss => der.tlvLen(a.oidBytes().len) + k.parameters.len,
        else => der.tlvLen(a.oidBytes().len),
    };
    const private_len = privateFieldLen(k);
    const public_len = if (v2) der.tlvLen(1 + k.public.?.len) else 0;
    w.header(0x30, der.tlvLen(1) + der.tlvLen(alg_len) + der.tlvLen(private_len) + public_len);
    w.tlv(0x02, &.{if (v2) 1 else 0});
    w.header(0x30, alg_len);
    if (a.isEc()) {
        w.tlv(0x06, &oid.ec_public_key);
        w.tlv(0x06, a.oidBytes());
    } else {
        w.tlv(0x06, a.oidBytes());
        if (a == .rsa) w.tlv(0x05, &.{});
        if (a == .rsa_pss) w.bytes(k.parameters);
    }
    w.header(0x04, private_len);
    writePrivateField(&w, k);
    if (v2) {
        w.header(0x81, 1 + k.public.?.len);
        w.byte(0);
        w.bytes(k.public.?);
    }
    return w.finish();
}

/// An EC `k` as SEC1 ECPrivateKey with `[0]` curve and, when `k.public` is
/// set, `[1]` public key (`openssl ec`'s shape).
pub fn writeSec1(out: []u8, k: PrivateKey) WriteError![]u8 {
    if (!k.algorithm.isEc()) return error.MalformedKey;
    try checkWritable(k);
    var w = der.Writer.init(out);
    writeEcPrivateKey(&w, k, true);
    return w.finish();
}

/// `k` in its own `encoding`: PKCS#8, SEC1, or (RSA) the PKCS#1 DER itself.
pub fn writePrivateKeyDer(out: []u8, k: PrivateKey) WriteError![]u8 {
    return switch (k.encoding) {
        .pkcs8 => writePkcs8(out, k),
        .sec1 => writeSec1(out, k),
        .pkcs1 => {
            try checkWritable(k);
            if (k.public != null) return error.MalformedKey; // PKCS#1 carries none
            if (out.len < k.secret.len) return error.NoSpaceLeft;
            @memcpy(out[0..k.secret.len], k.secret);
            return out[0..k.secret.len];
        },
    };
}

/// `writePrivateKeyDer` armoured as PEM under `k.encoding`'s label. The DER
/// exists only in a wiped stack buffer; the base64 is constant time.
pub fn writePrivateKeyPem(out: []u8, k: PrivateKey) WriteError![]u8 {
    return writePrivateKeyPemWithHeaders(out, k, &.{});
}

/// `writePrivateKeyPem` with RFC 1421 header lines between the BEGIN line and
/// the body (Go's `pem.Block.Headers`; see `pem.encodeWithHeaders` for their
/// order and the checks). The headers are public text: this does not encrypt
/// anything, and writing `Proc-Type: 4,ENCRYPTED` over a plain key makes a
/// file no reader accepts.
pub fn writePrivateKeyPemWithHeaders(out: []u8, k: PrivateKey, headers: []const pem.Header) WriteError![]u8 {
    return burn.run(burn.pem_write_burn, WriteError![]u8, writePrivateKeyPemBody, .{ out, k, headers });
}

fn writePrivateKeyPemBody(out: []u8, k: PrivateKey, headers: []const pem.Header) WriteError![]u8 {
    var buf: [max_private_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const bytes = writePrivateKeyDer(&buf, k) catch |err| return switch (err) {
        error.NoSpaceLeft => error.MalformedKey, // larger than any key `checkWritable` admits
        else => err,
    };
    return pem.encodeWithHeaders(out, k.encoding.pemLabel(), headers, bytes) catch |err| switch (err) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        error.InvalidPem => error.MalformedKey, // a header name or value outside RFC 1421's shape; the labels are fixed and valid
    };
}

/// `pk` as SubjectPublicKeyInfo.
pub fn writeSpki(out: []u8, pk: PublicKey) WriteError![]u8 {
    const a = pk.algorithm;
    if (a.isEc()) {
        checkPoint(a, pk.key) catch return error.MalformedKey;
    } else if (a.isRsa()) {
        checkPkcs1Public(pk.key) catch return error.MalformedKey;
        if (a == .rsa_pss) try checkPssParams(pk.parameters);
    } else if (pk.key.len != a.publicLen().?) return error.MalformedKey;
    if (a != .rsa_pss and pk.parameters.len != 0) return error.MalformedKey;

    const alg_len = switch (a) {
        .ec_p256, .ec_p384, .ec_p521, .ec_secp256k1 => der.tlvLen(oid.ec_public_key.len) + der.tlvLen(a.oidBytes().len),
        .rsa => der.tlvLen(a.oidBytes().len) + der.tlvLen(0),
        .rsa_pss => der.tlvLen(a.oidBytes().len) + pk.parameters.len,
        else => der.tlvLen(a.oidBytes().len),
    };
    var w = der.Writer.init(out);
    w.header(0x30, der.tlvLen(alg_len) + der.tlvLen(1 + pk.key.len));
    w.header(0x30, alg_len);
    if (a.isEc()) {
        w.tlv(0x06, &oid.ec_public_key);
        w.tlv(0x06, a.oidBytes());
    } else {
        w.tlv(0x06, a.oidBytes());
        if (a == .rsa) w.tlv(0x05, &.{});
        if (a == .rsa_pss) w.bytes(pk.parameters);
    }
    w.header(0x03, 1 + pk.key.len);
    w.byte(0);
    w.bytes(pk.key);
    return w.finish();
}

/// An RSA `pk` as a PKCS#1 `RSA PUBLIC KEY` PEM block (Go's
/// `MarshalPKCS1PublicKey` armoured): `pk.key` itself.
pub fn writeRsaPublicKeyPem(out: []u8, pk: PublicKey) WriteError![]u8 {
    if (pk.algorithm != .rsa or pk.parameters.len != 0) return error.MalformedKey;
    checkPkcs1Public(pk.key) catch return error.MalformedKey;
    return pem.encode(out, "RSA PUBLIC KEY", pk.key) catch |err| switch (err) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        error.InvalidPem => unreachable, // fixed, valid label
    };
}

/// `writeSpki` as a `PUBLIC KEY` PEM block.
pub fn writePublicKeyPem(out: []u8, pk: PublicKey) WriteError![]u8 {
    var buf: [max_public_der_len]u8 = undefined;
    const bytes = writeSpki(&buf, pk) catch |err| return switch (err) {
        error.NoSpaceLeft => error.MalformedKey,
        else => err,
    };
    return pem.encode(out, "PUBLIC KEY", bytes) catch |err| switch (err) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        error.InvalidPem => unreachable, // fixed, valid label
    };
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// A BIT STRING's content with no unused bits (every key encoding's).
fn bitStringBytes(content: []const u8) ParseError![]const u8 {
    if (content.len < 1 or content[0] != 0) return error.MalformedKey;
    return content[1..];
}

/// SEC1 §2.3.3 point shape for `curve`: `04 X Y` or `02|03 X`. The
/// infinity point (`00`) is refused.
fn checkPoint(curve: Algorithm, p: []const u8) ParseError!void {
    const n = curve.secretLen().?;
    // P-521 coordinates are 66 bytes, as its scalars.
    if (p.len == 1 + 2 * n and p[0] == 0x04) return;
    if (p.len == 1 + n and (p[0] == 0x02 or p[0] == 0x03)) return;
    return error.MalformedKey;
}

/// RFC 8017 A.1 / RFC 4055 §1.2: rsaEncryption's parameters are NULL; a
/// missing NULL is accepted (Go and OpenSSL read both).
fn nullOrAbsentParams(alg: *der.Reader) ParseError!void {
    if (alg.atEnd()) return;
    const n = try alg.expect(0x05);
    if (n.len != 0) return error.MalformedKey;
    try alg.end();
}

/// RSASSA-PSS parameters: absent, or one SEQUENCE (returned as its whole
/// TLV, uninterpreted -- the `rsa` module owns its meaning).
fn pssParams(alg: *der.Reader) ParseError![]const u8 {
    if (alg.atEnd()) return &.{};
    const start = alg.pos;
    _ = try alg.expect(0x30);
    const tlv = alg.b[start..alg.pos];
    try alg.end();
    return tlv;
}

fn checkPssParams(p: []const u8) WriteError!void {
    if (p.len == 0) return;
    var r = der.Reader.init(p);
    _ = r.expect(0x30) catch return error.MalformedKey;
    r.end() catch return error.MalformedKey;
}

/// RFC 8017 A.1.2: version 0 (two-prime) is exactly eight INTEGERs;
/// version 1 (multi-prime) adds `otherPrimeInfos`, a non-empty SEQUENCE of
/// SEQUENCEs. The numbers' values (sign, minimality, consistency) are the
/// `rsa` module's to check.
fn checkPkcs1Private(bytes: []const u8) ParseError!void {
    var top = der.Reader.init(bytes);
    var s = try top.sub(0x30);
    try top.end();
    const version = try s.smallInt();
    if (version > 1) return error.MalformedKey;
    for (0..8) |_| _ = try integer(&s); // modulus .. coefficient
    if (version == 1) {
        var others = try s.sub(0x30);
        if (others.atEnd()) return error.MalformedKey;
        while (!others.atEnd()) _ = try others.expect(0x30);
    }
    try s.end();
}

fn checkPkcs1Public(bytes: []const u8) ParseError!void {
    var top = der.Reader.init(bytes);
    var s = try top.sub(0x30);
    try top.end();
    _ = try integer(&s);
    _ = try integer(&s);
    try s.end();
}

/// An INTEGER's content, which DER never leaves empty (X.690 §8.3.1).
fn integer(r: *der.Reader) ParseError![]const u8 {
    const c = try r.expect(0x02);
    if (c.len == 0) return error.MalformedKey;
    return c;
}

/// PKCS#8 `attributes [0] IMPLICIT SET OF Attribute`: each one a SEQUENCE
/// { type OID, values SET }. Read for shape only, then skipped.
fn checkAttributes(content: []const u8) ParseError!void {
    var r = der.Reader.init(content);
    while (!r.atEnd()) {
        var a = try r.sub(0x30);
        _ = try a.expect(0x06);
        _ = try a.expect(0x31);
        try a.end();
    }
}

/// `raw` (big-endian, at most `n.len` octets, left-padded) in [1, n), in
/// constant time in `raw`'s bytes; only the verdict is revealed.
fn scalarInRange(raw: []const u8, n: []const u8) bool {
    std.debug.assert(raw.len <= n.len); // checked by the only caller
    const pad = n.len - raw.len;
    var borrow: u8 = 0;
    var nonzero: u8 = 0;
    var i = n.len;
    while (i > 0) {
        i -= 1;
        const b: u8 = if (i >= pad) raw[i - pad] else 0; // `pad` is public
        const d: u16 = @as(u16, b) -% n[i] -% borrow;
        borrow = @truncate(d >> 15);
        nonzero |= b;
    }
    // borrow = 1 iff raw < n.
    return (borrow & @intFromBool(nonzero != 0)) == 1;
}

/// The fields of `k` fit its algorithm and encoding.
fn checkWritable(k: PrivateKey) WriteError!void {
    const a = k.algorithm;
    switch (k.encoding) {
        .pkcs8 => {},
        .sec1 => if (!a.isEc()) return error.MalformedKey,
        .pkcs1 => if (a != .rsa) return error.MalformedKey,
    }
    if (a != .rsa_pss and k.parameters.len != 0) return error.MalformedKey;
    if (!a.isPq() and (k.pq_form != null or k.expanded.len != 0)) return error.MalformedKey;
    if (a.isEc()) {
        const n = a.secretLen().?;
        if (k.secret.len == 0 or k.secret.len > n or !scalarInRange(k.secret, a.order().?)) return error.MalformedKey;
        if (k.public) |p| checkPoint(a, p) catch return error.MalformedKey;
    } else if (a.isRsa()) {
        checkPkcs1Private(k.secret) catch return error.MalformedKey;
        if (k.secret.len > max_private_der_len - 64) return error.MalformedKey;
        if (a == .rsa_pss) try checkPssParams(k.parameters);
        if (k.public) |p| checkPkcs1Public(p) catch return error.MalformedKey; // PKCS#8 v2
    } else if (a.isPq()) {
        const form = k.pq_form orelse return error.MalformedKey;
        switch (form) {
            .seed => if (k.secret.len != a.secretLen().? or k.expanded.len != 0) return error.MalformedKey,
            .expanded => if (k.secret.len != a.expandedLen().? or k.expanded.len != 0) return error.MalformedKey,
            .both => if (k.secret.len != a.secretLen().? or k.expanded.len != a.expandedLen().?) return error.MalformedKey,
        }
        if (k.public) |p| if (p.len != a.publicLen().?) return error.MalformedKey;
    } else {
        if (k.secret.len != a.secretLen().?) return error.MalformedKey;
        if (k.public) |p| if (p.len != a.publicLen().?) return error.MalformedKey;
    }
}

/// Length of the PKCS#8 `privateKey` OCTET STRING's content.
fn privateFieldLen(k: PrivateKey) usize {
    const a = k.algorithm;
    if (a.isEc()) return der.tlvLen(ecPrivateKeyContentLen(k, false));
    if (a.isRsa()) return k.secret.len;
    if (a.isPq()) return switch (k.pq_form.?) {
        .seed, .expanded => der.tlvLen(k.secret.len),
        .both => der.tlvLen(der.tlvLen(k.secret.len) + der.tlvLen(k.expanded.len)),
    };
    return der.tlvLen(k.secret.len); // CurvePrivateKey
}

fn writePrivateField(w: *der.Writer, k: PrivateKey) void {
    const a = k.algorithm;
    if (a.isEc()) return writeEcPrivateKey(w, k, false);
    if (a.isRsa()) return w.bytes(k.secret);
    if (a.isPq()) return switch (k.pq_form.?) {
        .seed => w.tlv(0x80, k.secret),
        .expanded => w.tlv(0x04, k.secret),
        .both => {
            w.header(0x30, der.tlvLen(k.secret.len) + der.tlvLen(k.expanded.len));
            w.tlv(0x04, k.secret);
            w.tlv(0x04, k.expanded);
        },
    };
    w.tlv(0x04, k.secret);
}

/// The ECPrivateKey SEQUENCE's content length.
fn ecPrivateKeyContentLen(k: PrivateKey, with_params: bool) usize {
    const n = k.algorithm.secretLen().?;
    var len = der.tlvLen(1) + der.tlvLen(n);
    if (with_params) len += der.tlvLen(der.tlvLen(k.algorithm.oidBytes().len));
    if (k.public) |p| len += der.tlvLen(der.tlvLen(1 + p.len));
    return len;
}

/// RFC 5915 ECPrivateKey, the scalar padded to the order's length (RFC 5915
/// §3: "ceiling (log2(n)/8)" octets).
fn writeEcPrivateKey(w: *der.Writer, k: PrivateKey, with_params: bool) void {
    const n = k.algorithm.secretLen().?;
    w.header(0x30, ecPrivateKeyContentLen(k, with_params));
    w.tlv(0x02, &.{1});
    w.header(0x04, n);
    for (0..n - k.secret.len) |_| w.byte(0);
    w.bytes(k.secret);
    if (with_params) {
        w.header(0xa0, der.tlvLen(k.algorithm.oidBytes().len));
        w.tlv(0x06, k.algorithm.oidBytes());
    }
    if (k.public) |p| {
        w.header(0xa1, der.tlvLen(1 + p.len));
        w.header(0x03, 1 + p.len);
        w.byte(0);
        w.bytes(p);
    }
}

fn parsePq(k: *PrivateKey, private: []const u8) ParseError!void {
    const a = k.algorithm;
    var r = der.Reader.init(private);
    switch (r.peekTag() orelse return error.MalformedKey) {
        0x80 => {
            k.secret = try r.expect(0x80);
            k.pq_form = .seed;
            if (k.secret.len != a.secretLen().?) return error.MalformedKey;
        },
        0x04 => {
            k.secret = try r.expect(0x04);
            k.pq_form = .expanded;
            if (k.secret.len != a.expandedLen().?) return error.MalformedKey;
        },
        0x30 => {
            var both = try r.sub(0x30);
            k.secret = try both.expect(0x04);
            k.expanded = try both.expect(0x04);
            try both.end();
            k.pq_form = .both;
            if (k.secret.len != a.secretLen().? or k.expanded.len != a.expandedLen().?) return error.MalformedKey;
        },
        else => return error.MalformedKey,
    }
    try r.end();
}

test {
    _ = der;
    _ = pem;
    _ = pbes2;
    _ = @import("tests.zig");
    _ = @import("pbes2_test.zig");
    _ = @import("fuzz.zig");
    _ = @import("mlkem_test.zig");
    _ = @import("stackprobe_test.zig");
}
