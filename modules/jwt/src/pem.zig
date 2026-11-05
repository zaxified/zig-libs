// SPDX-License-Identifier: MIT

//! Keys from PEM (golang-jwt's `ParseRSAPrivateKeyFromPEM`,
//! `ParseECPrivateKeyFromPEM`, `ParseEdPrivateKeyFromPEM` and their
//! public-key counterparts), over the `keycodec` module: PKCS#8, SEC1 and
//! PKCS#1 private keys, SPKI and PKCS#1 public keys.
//!
//! Every check the codec leaves to the key type is made here: an EC point is
//! decoded by the curve module (on-curve), the RSA key by `rsa` (`openssl
//! rsa -check`'s consistency), an ML-DSA `both` key's expanded half must be
//! its seed's. An ML-DSA key in the expanded-only form is refused: std has no
//! call that recomputes its `K`, `tr`, `t0`, so a damaged one would sign
//! garbage (`tlsserver` refuses it for the same reason). A public key the
//! private encoding carries is not used: the pair is derived from the secret.

const std = @import("std");
const keycodec = @import("keycodec");
const root = @import("root.zig");
const encode_mod = @import("encode.zig");
const burn = @import("burn.zig");

const Key = root.Key;
const KeyError = root.KeyError;
const SigningKey = encode_mod.SigningKey;

/// A private key loaded from PEM and held by value; a `SigningKey` borrows
/// from it, so it must not move while one is in use. Large: an ML-DSA-87
/// pair is std's expanded key (`@sizeOf(PrivateKey)` ~ 110 KiB) -- keep it
/// in static or heap storage, not on a small stack. `deinit` wipes it.
pub const PrivateKey = union(enum) {
    ecdsa_p256: root.EcdsaP256Sha256.KeyPair,
    ecdsa_p384: root.EcdsaP384Sha384.KeyPair,
    ecdsa_p521: root.EcdsaP521Sha512.KeyPair,
    ed25519: root.Ed25519.KeyPair,
    rsa: root.rsa.KeyPair,
    ml_dsa_44: root.MlDsa44.KeyPair,
    ml_dsa_65: root.MlDsa65.KeyPair,
    ml_dsa_87: root.MlDsa87.KeyPair,

    /// Loads the first private key of `text` (`PRIVATE KEY`, `EC PRIVATE
    /// KEY`, `RSA PRIVATE KEY`; other blocks are skipped) into `out`. Every
    /// error is `InvalidKey` (and `out` is zeroed): a malformed or encrypted
    /// key, an algorithm JWS does not sign with (X25519, secp256k1, ML-KEM,
    /// ...), an EC scalar out of range, an RSA key `rsa` finds inconsistent
    /// or below 2048 bits, an ML-DSA key in the expanded-only form or whose
    /// two halves disagree. Runs under a dead-stack burn; an ML-DSA key
    /// needs up to 1.3 MiB of stack for its expansion (ML-DSA-87).
    pub fn fromPem(out: *PrivateKey, text: []const u8) KeyError!void {
        return burn.run(burn.pem_key_burn, KeyError!void, fromPemBody, .{ out, text });
    }

    fn fromPemBody(out: *PrivateKey, text: []const u8) KeyError!void {
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
        var der_buf: [keycodec.max_private_der_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &der_buf);
        const k = keycodec.parsePrivateKeyPem(text, &der_buf) catch return error.InvalidKey;
        switch (k.algorithm) {
            .ec_p256 => try ec(root.EcdsaP256Sha256, .ecdsa_p256, out, &k),
            .ec_p384 => try ec(root.EcdsaP384Sha384, .ecdsa_p384, out, &k),
            .ec_p521 => try ec(root.EcdsaP521Sha512, .ecdsa_p521, out, &k),
            .ed25519 => {
                const kp = root.Ed25519.KeyPair.generateDeterministic(k.secret[0..32].*) catch return error.InvalidKey;
                out.* = .{ .ed25519 = kp };
            },
            .rsa => {
                out.* = .{ .rsa = undefined };
                root.rsa.SecretKey.fromDer(&out.rsa.secret_key, k.secret) catch return error.InvalidKey;
                out.rsa.public_key = out.rsa.secret_key.publicKey();
                if (out.rsa.public_key.bits() < root.rsa_min_bits) return error.InvalidKey;
            },
            .ml_dsa_44 => try burn.run(burn.mldsa_key_burn.ml_dsa_44, KeyError!void, mlDsa, .{ root.MlDsa44, .ml_dsa_44, out, &k }),
            .ml_dsa_65 => try burn.run(burn.mldsa_key_burn.ml_dsa_65, KeyError!void, mlDsa, .{ root.MlDsa65, .ml_dsa_65, out, &k }),
            .ml_dsa_87 => try burn.run(burn.mldsa_key_burn.ml_dsa_87, KeyError!void, mlDsa, .{ root.MlDsa87, .ml_dsa_87, out, &k }),
            // RSASSA-PSS-only keys (id-RSASSA-PSS), Ed448, X25519/X448,
            // secp256k1, ML-KEM: no JWS algorithm in this module signs with them.
            else => return error.InvalidKey,
        }
    }

    fn ec(comptime E: type, comptime tag: std.meta.Tag(PrivateKey), out: *PrivateKey, k: *const keycodec.PrivateKey) KeyError!void {
        var sk: E.SecretKey = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        k.scalarInto(&sk.bytes) catch return error.InvalidKey;
        out.* = @unionInit(PrivateKey, @tagName(tag), undefined);
        E.KeyPair.fromSecretKeyInto(&@field(out, @tagName(tag)), &sk) catch return error.InvalidKey;
    }

    fn mlDsa(comptime M: type, comptime tag: std.meta.Tag(PrivateKey), out: *PrivateKey, k: *const keycodec.PrivateKey) KeyError!void {
        const form = k.pq_form orelse return error.InvalidKey;
        if (form == .expanded) return error.InvalidKey; // see the file comment
        const keys = M.newKeyFromSeed(k.secret[0..M.seed_length]);
        out.* = @unionInit(PrivateKey, @tagName(tag), .{ .public_key = keys.pk, .secret_key = keys.sk });
        if (form == .both) {
            var own = keys.sk.toBytes();
            defer std.crypto.secureZero(u8, &own);
            if (!std.crypto.timing_safe.eql([M.SecretKey.encoded_length]u8, own, k.expanded[0..M.SecretKey.encoded_length].*))
                return error.InvalidKey;
        }
    }

    /// The `SigningKey` for the key's own algorithm: ES256/ES384/ES512,
    /// EdDSA, ML-DSA-*, and RS256 for an RSA key (`rsaSigningKey` picks
    /// another RSA algorithm).
    pub fn signingKey(self: *const PrivateKey) SigningKey {
        return switch (self.*) {
            .ecdsa_p256 => |*kp| .{ .es256 = kp },
            .ecdsa_p384 => |*kp| .{ .es384 = kp },
            .ecdsa_p521 => |*kp| .{ .es512 = kp },
            .ed25519 => |*kp| .{ .ed25519 = kp },
            .rsa => |*kp| .{ .rs256 = kp },
            .ml_dsa_44 => |*kp| .{ .ml_dsa_44 = kp },
            .ml_dsa_65 => |*kp| .{ .ml_dsa_65 = kp },
            .ml_dsa_87 => |*kp| .{ .ml_dsa_87 = kp },
        };
    }

    /// An RSA key's `SigningKey` for `alg`: RS256/384/512, or PS256/384/512
    /// with the CSPRNG `random` (required for PS*, ignored for RS*).
    /// `InvalidKey` for a non-RSA key, another `alg`, or PS* without `random`.
    pub fn rsaSigningKey(self: *const PrivateKey, alg: root.Alg, random: ?std.Random) KeyError!SigningKey {
        const kp = switch (self.*) {
            .rsa => |*kp| kp,
            else => return error.InvalidKey,
        };
        return switch (alg) {
            .RS256 => .{ .rs256 = kp },
            .RS384 => .{ .rs384 = kp },
            .RS512 => .{ .rs512 = kp },
            .PS256 => .{ .ps256 = .{ .key = kp, .random = random orelse return error.InvalidKey } },
            .PS384 => .{ .ps384 = .{ .key = kp, .random = random orelse return error.InvalidKey } },
            .PS512 => .{ .ps512 = .{ .key = kp, .random = random orelse return error.InvalidKey } },
            else => error.InvalidKey,
        };
    }

    /// The matching verification key.
    pub fn verificationKey(self: *const PrivateKey) Key {
        return self.signingKey().verificationKey();
    }

    /// Wipes the key.
    pub fn deinit(self: *PrivateKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }
};

/// `Key.fromPem`: the first `PUBLIC KEY` (SPKI) or `RSA PUBLIC KEY` (PKCS#1)
/// block of `text`. EC points are checked on-curve by the curve module, RSA
/// keys by `rsa` and the 2048-bit floor. A certificate is not read (golang-
/// jwt's `ParseRSAPublicKeyFromPEM` also takes one): its SPKI comes from
/// `x509.spkiOf`, whose DER `Key.fromSpki` reads.
pub fn publicKeyFromPem(text: []const u8) KeyError!Key {
    var buf: [keycodec.max_public_der_len]u8 = undefined;
    const pk = keycodec.parsePublicKeyPem(text, &buf) catch return error.InvalidKey;
    return fromParsed(pk);
}

/// `Key.fromSpki`: a SubjectPublicKeyInfo DER.
pub fn publicKeyFromSpki(der: []const u8) KeyError!Key {
    const pk = keycodec.parseSpki(der) catch return error.InvalidKey;
    return fromParsed(pk);
}

fn fromParsed(pk: keycodec.PublicKey) KeyError!Key {
    switch (pk.algorithm) {
        .ec_p256 => return .{ .ecdsa_p256 = root.EcdsaP256Sha256.PublicKey.fromSec1(pk.key) catch return error.InvalidKey },
        .ec_p384 => return .{ .ecdsa_p384 = root.EcdsaP384Sha384.PublicKey.fromSec1(pk.key) catch return error.InvalidKey },
        .ec_p521 => return .{ .ecdsa_p521 = root.EcdsaP521Sha512.PublicKey.fromSec1(pk.key) catch return error.InvalidKey },
        .ed25519 => return Key.ed25519FromBytes(pk.key[0..32].*),
        .rsa => {
            const p = root.rsa.PublicKey.fromDer(pk.key) catch return error.InvalidKey;
            return Key.rsaFromPublicKey(&p);
        },
        .ml_dsa_44 => return Key.mlDsa44FromBytes(pk.key[0..root.MlDsa44.PublicKey.encoded_length].*),
        .ml_dsa_65 => return Key.mlDsa65FromBytes(pk.key[0..root.MlDsa65.PublicKey.encoded_length].*),
        .ml_dsa_87 => return Key.mlDsa87FromBytes(pk.key[0..root.MlDsa87.PublicKey.encoded_length].*),
        else => return error.InvalidKey,
    }
}
