// SPDX-License-Identifier: MIT
//! DHKEM (RFC 9180 §4 / §7.1) — the KEM half of HPKE: `Encap`/`Decap` (base
//! mode) and `AuthEncap`/`AuthDecap` (auth mode, §4.1 "Authentication using
//! Asymmetric Keys"), instantiated over the two DH groups this repo's std
//! toolchain can drive without a C dependency: X25519
//! (`dhkem_x25519_hkdf_sha256`) and P-256 (`dhkem_p256_hkdf_sha256`), both
//! paired with HKDF-SHA256 (RFC 9180 §7.1 Table 2 only lists KEMs with
//! their own fixed internal KDF — the KEM's KDF is independent of the
//! outer ciphersuite's `kdf_id`).
//!
//! **Everything here is REAL** (crypto-implementation pass done —
//! KAT-validated against RFC 9180 Appendix A.1/A.3, see `kat_rfc9180.zig`;
//! `AuthEncap`/`AuthDecap` and `P256Kem.deriveKeyPair` included, against
//! A.1.3/A.1.4 and A.3.3/A.3.4's published `enc`/`shared_secret` and
//! `ikmS`/`skSm`/`pkSm`).
//! `encapDeterministic`/`authEncapDeterministic` take the ephemeral keypair
//! as a parameter (rather than drawing one from `std.Io`'s randomness
//! internally) so the RFC 9180 Appendix A known-answer vectors — which fix
//! `skEm`/`pkEm` — can drive them byte-exact; `encap`/`authEncap` are thin
//! `generateKeyPair(io)` + `*Deterministic` wrappers for real callers.

const std = @import("std");
const suite = @import("suite.zig");
// P-256 curve group for the DHKEM(P-256, …) suite from the asm-accelerated
// `p256` module (byte-exact to `std.crypto.ecc.P256`). The X25519 KEM path
// stays on std (p256 covers only the P-256 curve).
const P256 = @import("p256").P256;

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// Errors an `Encap`/`AuthEncap` can return (RFC 9180 §4/§7.1 doesn't
/// itself name failure modes beyond "SerializeError"/"DeserializeError"
/// for malformed keys — X25519/P-256 DH can also reject a low-order/
/// identity result, RFC 9180 §7.1.1/§7.1.2).
pub const EncapError = error{
    /// The DH computation hit the identity element / a low-order point
    /// (X25519 all-zero output, RFC 7748 §6.1; P-256 point-at-infinity) —
    /// RFC 9180 §7.1.1/§7.1.2 both call this out as a required check, not
    /// an edge case to silently ignore.
    DhFailed,
    /// `pkR`/`pkS` failed to deserialize (P-256 SEC1 decoding: not on the
    /// curve, non-canonical coordinates, or a malformed encoding — RFC
    /// 9180 §7.1.1's "DeserializeError"). X25519's raw-32-byte keys never
    /// hit this (every 32-byte string is a valid u-coordinate input).
    DeserializeError,
};

/// Mirrors `EncapError` for the receiver side (`Decap`/`AuthDecap`), plus
/// a malformed `enc`/public-key deserialization failure.
pub const DecapError = error{
    DhFailed,
    DeserializeError,
};

/// RFC 9180 §4.1 `ExtractAndExpand(dh, kem_context)` — the one derivation
/// both KEMs share (their internal KDF is HKDF-SHA256 for every KEM this
/// module instantiates, RFC 9180 §7.1 Table 2): `eae_prk =
/// LabeledExtract("", "eae_prk", dh)`; `shared_secret =
/// LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)` — both
/// under `kemSuiteId(kem_id)` ("KEM" || kem_id), NOT the outer HPKE
/// `suiteId` (which also folds in kdf_id/aead_id; §7.2.1 vs §4.1).
fn extractAndExpand(
    comptime kem_id: u16,
    comptime Nsecret: usize,
    dh: []const u8,
    kem_context: []const u8,
) [Nsecret]u8 {
    const kem_suite_id = comptime suite.kemSuiteId(kem_id);
    const eae_prk = suite.labeledExtract(HkdfSha256, &kem_suite_id, "", "eae_prk", dh);
    var shared_secret: [Nsecret]u8 = undefined;
    // kem_context tops out at 195 bytes (P-256 auth mode: 3 × 65-byte SEC1
    // points) — far inside labeledExpand's 512-byte scratch, so
    // error.LabelTooLong is structurally unreachable here.
    suite.labeledExpand(HkdfSha256, &kem_suite_id, eae_prk, "shared_secret", kem_context, &shared_secret) catch unreachable;
    return shared_secret;
}

// ── DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1, kem_id 0x0020 ───────────

/// `dhkem_x25519_hkdf_sha256` (RFC 9180 §7.1 Table 2): Nsecret = Nsk = Npk
/// = 32 (X25519's own widths; Nsecret is HKDF-SHA256's `Nh`, which happens
/// to also be 32 here — coincidence of both being SHA-256-sized, not a
/// spec requirement that Nsecret == Npk).
pub const X25519Kem = struct {
    pub const kem_id: u16 = @intFromEnum(suite.KemId.dhkem_x25519_hkdf_sha256);
    /// KEM shared-secret width (RFC 9180 Table 2's `Nsecret`) — HKDF-SHA256's
    /// `Nh`.
    pub const Nsecret: usize = 32;
    pub const Npk: usize = std.crypto.dh.X25519.public_length; // 32
    pub const Nsk: usize = std.crypto.dh.X25519.secret_length; // 32

    pub const KeyPair = std.crypto.dh.X25519.KeyPair;
    pub const PublicKey = [Npk]u8;
    /// `enc` on the wire is just the ephemeral public key (RFC 9180 §4.1).
    pub const EncappedKey = [Npk]u8;

    /// The `ExtractAndExpand(dh, kem_context)` result plus the `enc` the
    /// sender must transmit alongside the ciphertext.
    pub const Encapped = struct {
        shared_secret: [Nsecret]u8,
        enc: EncappedKey,
    };

    /// Trivial passthrough — no domain logic beyond calling std's
    /// CSPRNG-backed `KeyPair.generate` (nothing HPKE-specific to get
    /// wrong; `deriveKeyPair` below is the ikm-seeded RFC 9180 form).
    pub fn generateKeyPair(io: std.Io) KeyPair {
        return KeyPair.generate(io);
    }

    /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for X25519: `dkp_prk =
    /// LabeledExtract("", "dkp_prk", ikm)` (using `kemSuiteId(kem_id)`,
    /// NOT the outer `suiteId`); `sk = LabeledExpand(dkp_prk, "sk", "",
    /// 32)`; clamp `sk` per RFC 7748 (X25519 `KeyPair.generateDeterministic`
    /// already clamps internally, so this reduces to: derive the 32-byte
    /// seed via LabeledExpand, then call
    /// `std.crypto.dh.X25519.KeyPair.generateDeterministic(seed)`). No
    /// rejection-sampling loop is needed for X25519 (every 32-byte string
    /// is a valid clamped scalar), unlike `P256Kem.deriveKeyPair` below.
    ///
    /// KAT: reproduces RFC 9180 A.1.1's `skEm`/`pkEm` from `ikmE` (and
    /// `skRm`/`pkRm` from `ikmR`) byte-exact — proving std stores the
    /// derived seed as `secret_key` verbatim (unclamped at rest, clamped
    /// at use inside `scalarmult`, exactly the RFC's serialization).
    pub fn deriveKeyPair(ikm: []const u8) KeyPair {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        const dkp_prk = suite.labeledExtract(HkdfSha256, &kem_suite_id, "", "dkp_prk", ikm);
        var sk: [Nsk]u8 = undefined;
        // Empty info + tiny label: LabelTooLong structurally unreachable.
        suite.labeledExpand(HkdfSha256, &kem_suite_id, dkp_prk, "sk", "", &sk) catch unreachable;
        // A clamped X25519 scalar (high bit pattern forced by RFC 7748
        // clamping) times the basepoint can never land on the identity, so
        // generateDeterministic's IdentityElementError is unreachable.
        return KeyPair.generateDeterministic(sk) catch unreachable;
    }

    /// RFC 9180 §4.1 `Encap(pkR)`, real-randomness entry point: draw a
    /// fresh ephemeral keypair via `io`, then defer to
    /// `encapDeterministic`.
    pub fn encap(pkR: PublicKey, io: std.Io) EncapError!Encapped {
        return encapDeterministic(pkR, generateKeyPair(io));
    }

    /// RFC 9180 §4.1 `Encap(pkR)`, ephemeral-injected for KAT
    /// reproducibility (RFC 9180 Appendix A fixes `skEm`/`pkEm` per
    /// vector — this is the seam a test drives directly, mirroring how
    /// this repo's `bip340` takes `aux_rand` and `jwe`'s A.3 KAT replays a
    /// fixed CEK/IV stream instead of drawing real randomness).
    ///
    /// Recipe (RFC 9180 §4.1, Sections 7.1.1's `Encap`):
    /// ```text
    /// dh = DH(skE, pkR)                          // X25519.scalarmult(eph.secret_key, pkR)
    /// enc = pkE                                  // eph.public_key
    /// pkRm = SerializePublicKey(pkR)              // pkR itself (already raw 32 bytes)
    /// kem_context = enc || pkRm
    /// shared_secret = ExtractAndExpand(dh, kem_context)
    /// ```
    /// where `ExtractAndExpand` (§7.1.1) is:
    /// ```text
    /// suite_id = kemSuiteId(0x0020)                          // suite.zig
    /// eae_prk = LabeledExtract(suite_id, "", "eae_prk", dh)  // suite.zig
    /// shared_secret = LabeledExpand(suite_id, eae_prk, "shared_secret", kem_context, Nsecret)
    /// ```
    /// `dh == [0u8;32]` (the X25519 all-zero low-order result, RFC 7748
    /// §6.1) MUST fail with `error.DhFailed`, not silently proceed —
    /// std's `scalarmult` performs that rejection itself
    /// (`IdentityElementError`), mapped to `error.DhFailed` here.
    ///
    /// KAT: RFC 9180 A.1.1 `enc`/`shared_secret`, byte-exact.
    pub fn encapDeterministic(pkR: PublicKey, eph: KeyPair) EncapError!Encapped {
        const dh = std.crypto.dh.X25519.scalarmult(eph.secret_key, pkR) catch return error.DhFailed;
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR;
        return .{
            .shared_secret = extractAndExpand(kem_id, Nsecret, &dh, &kem_context),
            .enc = eph.public_key,
        };
    }

    /// RFC 9180 §4.1 `Decap(enc, skR)` — the mirror of `encapDeterministic`:
    /// ```text
    /// pkE = DeserializePublicKey(enc)             // enc itself, already raw
    /// dh = DH(skR, pkE)                           // X25519.scalarmult(skR.secret_key, enc)
    /// pkRm = SerializePublicKey(pk(skR))          // skR.public_key
    /// kem_context = enc || pkRm
    /// shared_secret = ExtractAndExpand(dh, kem_context)   // same as encapDeterministic
    /// ```
    /// Must produce the IDENTICAL `shared_secret` `encapDeterministic`
    /// computed for the matching `(skE, pkR)` pair — the round-trip
    /// invariant the A.1.1 KAT checks.
    pub fn decap(enc: EncappedKey, skR: KeyPair) DecapError![Nsecret]u8 {
        const dh = std.crypto.dh.X25519.scalarmult(skR.secret_key, enc) catch return error.DhFailed;
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc;
        kem_context[Npk..].* = skR.public_key;
        return extractAndExpand(kem_id, Nsecret, &dh, &kem_context);
    }

    /// RFC 9180 §4.1 `AuthEncap(pkR, skS)` (auth / auth_psk modes): adds a
    /// second DH `dh2 = DH(skS, pkR)` binding the sender's static key,
    /// appends `pk(skS)` to the KEM context, and folds `dh || dh2` into a
    /// single `ExtractAndExpand` call:
    /// ```text
    /// dh  = DH(skE, pkR)
    /// dh2 = DH(skS, pkR)
    /// enc = pkE
    /// kem_context = enc || pkR || pk(skS)
    /// shared_secret = ExtractAndExpand(dh || dh2, kem_context)   // dh||dh2 is ONE 64-byte ikm to LabeledExtract
    /// ```
    /// Ephemeral-injected for KAT reproducibility, matching
    /// `encapDeterministic`. `dh || dh2` is ONE 64-byte ikm to
    /// `LabeledExtract`, not two separate extractions.
    pub fn authEncapDeterministic(pkR: PublicKey, skS: KeyPair, eph: KeyPair) EncapError!Encapped {
        var dh: [64]u8 = undefined;
        dh[0..32].* = std.crypto.dh.X25519.scalarmult(eph.secret_key, pkR) catch return error.DhFailed;
        dh[32..].* = std.crypto.dh.X25519.scalarmult(skS.secret_key, pkR) catch return error.DhFailed;
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR;
        kem_context[2 * Npk ..].* = skS.public_key;
        return .{
            .shared_secret = extractAndExpand(kem_id, Nsecret, &dh, &kem_context),
            .enc = eph.public_key,
        };
    }

    /// RFC 9180 §4.1 `AuthDecap(enc, skR, pkS)` — the mirror:
    /// ```text
    /// pkE = enc
    /// dh  = DH(skR, pkE)
    /// dh2 = DH(skR, pkS)
    /// kem_context = enc || pk(skR) || pkS
    /// shared_secret = ExtractAndExpand(dh || dh2, kem_context)
    /// ```
    pub fn authDecap(enc: EncappedKey, skR: KeyPair, pkS: PublicKey) DecapError![Nsecret]u8 {
        var dh: [64]u8 = undefined;
        dh[0..32].* = std.crypto.dh.X25519.scalarmult(skR.secret_key, enc) catch return error.DhFailed;
        dh[32..].* = std.crypto.dh.X25519.scalarmult(skR.secret_key, pkS) catch return error.DhFailed;
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS;
        return extractAndExpand(kem_id, Nsecret, &dh, &kem_context);
    }
};

// ── DHKEM(P-256, HKDF-SHA256) — RFC 9180 §7.1, kem_id 0x0010 ────────────

/// `dhkem_p256_hkdf_sha256` (RFC 9180 §7.1 Table 2): Nsecret = 32
/// (HKDF-SHA256's `Nh`), Nsk = 32 (a P-256 scalar), Npk = 65 (SEC1
/// UNCOMPRESSED point encoding, RFC 9180 §7.1.1's `SerializePublicKey` for
/// NIST curves — `0x04 || X || Y`, matching `std.crypto.ecc.P256.
/// toUncompressedSec1`/`.fromSec1`). std has no packaged "P-256 DH
/// keypair" type the way it does `std.crypto.dh.X25519.KeyPair`, so this
/// KEM defines its own `KeyPair` shape directly over
/// `std.crypto.ecc.P256`.
pub const P256Kem = struct {
    pub const kem_id: u16 = @intFromEnum(suite.KemId.dhkem_p256_hkdf_sha256);
    pub const Nsecret: usize = 32;
    pub const Npk: usize = 65; // SEC1 uncompressed: 0x04 || X(32) || Y(32)
    pub const Nsk: usize = 32;

    pub const PublicKey = [Npk]u8;
    pub const EncappedKey = [Npk]u8;

    pub const KeyPair = struct {
        secret_key: [Nsk]u8,
        public_key: PublicKey,
    };

    pub const Encapped = struct {
        shared_secret: [Nsecret]u8,
        enc: EncappedKey,
    };

    /// `sk = random scalar in [1, n-1]` via
    /// `P256.scalar.random(io)` (rejection-sampled
    /// uniform, not a raw byte draw — std owns the modular-reduction
    /// correctness), `pk = (P256.basePoint.mul(sk, .big)).toUncompressedSec1()`.
    pub fn generateKeyPair(io: std.Io) KeyPair {
        const sk = P256.scalar.random(io, .big);
        const pk_point = P256.basePoint.mul(sk, .big) catch unreachable; // basePoint * nonzero scalar never hits the identity
        return .{ .secret_key = sk, .public_key = pk_point.toUncompressedSec1() };
    }

    /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for P-256: same `dkp_prk`/
    /// `LabeledExpand(..., "candidate", ..., 32)` construction as X25519's
    /// `deriveKeyPair`, but with a REJECTION-SAMPLING LOOP (P-256 scalars
    /// must be `< n`, the group order — not every 32-byte string is
    /// valid): `for (counter = 0; counter < 256; counter++) { candidate =
    /// LabeledExpand(dkp_prk, "candidate", I2OSP(counter,1), 32);
    /// bytes_to_int_of_hash_reduce it against `n`; if in range, that's
    /// `sk` }` — RFC 9180 §7.1.3's `bitmask` is `0xFF` for P-256 (it only
    /// narrows for P-521), so the mask is kept as a literal no-op mirroring
    /// the spec pseudocode. A candidate is rejected iff it is zero or
    /// `>= n` (`P256.scalar.rejectNonCanonical`) — each rejection has
    /// probability ~2^-32 (the P-256 order is within 2^-32 of 2^256), so
    /// 256 consecutive rejections (the spec's `DeriveKeyPairError`) is
    /// cryptographically unreachable; this implementation fails closed
    /// with a panic there rather than widening the signature with an
    /// error no caller could meaningfully handle.
    pub fn deriveKeyPair(ikm: []const u8) KeyPair {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        const dkp_prk = suite.labeledExtract(HkdfSha256, &kem_suite_id, "", "dkp_prk", ikm);
        var counter: u16 = 0;
        while (counter <= 255) : (counter += 1) {
            const ctr = suite.i2osp(1, counter);
            var candidate: [Nsk]u8 = undefined;
            suite.labeledExpand(HkdfSha256, &kem_suite_id, dkp_prk, "candidate", &ctr, &candidate) catch unreachable;
            candidate[0] &= 0xff; // RFC 9180 §7.1.3 bitmask (0xFF for P-256)
            P256.scalar.rejectNonCanonical(candidate, .big) catch continue; // sk >= n
            if (std.mem.allEqual(u8, &candidate, 0)) continue; // sk == 0
            // basePoint * nonzero canonical scalar never hits the identity.
            const pk_point = P256.basePoint.mul(candidate, .big) catch unreachable;
            return .{ .secret_key = candidate, .public_key = pk_point.toUncompressedSec1() };
        }
        @panic("hpke: P-256 DeriveKeyPair exhausted 256 candidates (probability ~2^-8192; RFC 9180 7.1.3 DeriveKeyPairError)");
    }

    /// RFC 9180 §4.1/§7.1.2 `Encap(pkR)` for P-256 — same shape as
    /// `X25519Kem.encapDeterministic`, but the DH is a scalar-point
    /// multiply whose output is the shared point's X COORDINATE (RFC 9180
    /// §7.1.2's `DH(skX, pkY)`), not `X25519.scalarmult`'s already-scalar
    /// result:
    /// ```text
    /// pkR_point = P256.fromSec1(&pkR)              // reject invalid encoding -> error.DeserializeError
    /// shared_point = pkR_point.mul(eph.secret_key, .big)   // reject identity -> error.DhFailed
    /// dh = shared_point.affineCoordinates().x.toBytes(.big)   // the 32-byte X coordinate ONLY (not Y, not the point encoding)
    /// enc = eph.public_key
    /// kem_context = enc || pkR
    /// suite_id = kemSuiteId(0x0010)
    /// eae_prk = LabeledExtract(suite_id, "", "eae_prk", &dh)
    /// shared_secret = LabeledExpand(suite_id, eae_prk, "shared_secret", kem_context, 32)
    /// ```
    ///
    /// KAT: RFC 9180 A.3 `enc`/`shared_secret`, byte-exact.
    pub fn encapDeterministic(pkR: PublicKey, eph: KeyPair) EncapError!Encapped {
        const pkR_point = P256.fromSec1(&pkR) catch return error.DeserializeError;
        const shared_point = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR;
        return .{
            .shared_secret = extractAndExpand(kem_id, Nsecret, &dh, &kem_context),
            .enc = eph.public_key,
        };
    }

    pub fn encap(pkR: PublicKey, io: std.Io) EncapError!Encapped {
        return encapDeterministic(pkR, generateKeyPair(io));
    }

    /// Mirror of `encapDeterministic`: `dh = P256.fromSec1(&enc).mul(skR.secret_key,
    /// .big).affineCoordinates().x.toBytes(.big)`; `kem_context = enc ||
    /// skR.public_key`.
    pub fn decap(enc: EncappedKey, skR: KeyPair) DecapError![Nsecret]u8 {
        const enc_point = P256.fromSec1(&enc) catch return error.DeserializeError;
        const shared_point = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc;
        kem_context[Npk..].* = skR.public_key;
        return extractAndExpand(kem_id, Nsecret, &dh, &kem_context);
    }

    /// RFC 9180 §4.1 `AuthEncap(pkR, skS)` for P-256 — same `dh || dh2`
    /// fold as `X25519Kem.authEncapDeterministic`, with each `dh`/`dh2`
    /// being the 32-byte X coordinate (not the raw scalarmult output).
    pub fn authEncapDeterministic(pkR: PublicKey, skS: KeyPair, eph: KeyPair) EncapError!Encapped {
        const pkR_point = P256.fromSec1(&pkR) catch return error.DeserializeError;
        var dh: [64]u8 = undefined;
        const p1 = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        dh[0..32].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkR_point.mul(skS.secret_key, .big) catch return error.DhFailed;
        dh[32..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR;
        kem_context[2 * Npk ..].* = skS.public_key;
        return .{
            .shared_secret = extractAndExpand(kem_id, Nsecret, &dh, &kem_context),
            .enc = eph.public_key,
        };
    }

    pub fn authDecap(enc: EncappedKey, skR: KeyPair, pkS: PublicKey) DecapError![Nsecret]u8 {
        const enc_point = P256.fromSec1(&enc) catch return error.DeserializeError;
        const pkS_point = P256.fromSec1(&pkS) catch return error.DeserializeError;
        var dh: [64]u8 = undefined;
        const p1 = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[0..32].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkS_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[32..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS;
        return extractAndExpand(kem_id, Nsecret, &dh, &kem_context);
    }
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "X25519Kem: type widths match RFC 9180 Table 2" {
    try testing.expectEqual(@as(usize, 32), X25519Kem.Nsecret);
    try testing.expectEqual(@as(usize, 32), X25519Kem.Npk);
    try testing.expectEqual(@as(usize, 32), X25519Kem.Nsk);
    try testing.expectEqual(@as(u16, 0x0020), X25519Kem.kem_id);
}

test "P256Kem: type widths match RFC 9180 Table 2 (SEC1 uncompressed Npk=65)" {
    try testing.expectEqual(@as(usize, 32), P256Kem.Nsecret);
    try testing.expectEqual(@as(usize, 65), P256Kem.Npk);
    try testing.expectEqual(@as(usize, 32), P256Kem.Nsk);
    try testing.expectEqual(@as(u16, 0x0010), P256Kem.kem_id);
}

test "P256Kem: basePoint.mul + toUncompressedSec1 wiring produces a well-formed SEC1 point" {
    // A pure-math smoke test of the exact std composition
    // `generateKeyPair` uses (there's no RFC 9180 KAT for a fresh random
    // keypair to check against — `std.Io`-backed randomness needs a real
    // event-loop instance this pure-math test doesn't stand up). scalar =
    // 1 -> pk == the curve's own basePoint, uncompressed-encoded.
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const pk_point = P256.basePoint.mul(one, .big) catch unreachable;
    const pk = pk_point.toUncompressedSec1();
    try testing.expectEqual(@as(u8, 0x04), pk[0]); // SEC1 uncompressed tag
    try testing.expectEqual(@as(usize, 65), pk.len);
    try testing.expect(pk_point.equivalent(P256.basePoint));
}

test "DHKEM X25519 Encap/Decap: RFC 9180 A.1.1 enc/shared_secret, byte-exact" {
    // kat_rfc9180.zig owns the canonical copy of the A.1 vector bytes;
    // this test borrows them rather than duplicating the hex constants.
    const a1 = @import("kat_rfc9180.zig").a1;
    const eph = X25519Kem.KeyPair{ .secret_key = a1.skEm, .public_key = a1.pkEm };
    const got = try X25519Kem.encapDeterministic(a1.pkRm, eph);
    try testing.expectEqualSlices(u8, &a1.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &got.shared_secret);
    const skR = X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    const dec = try X25519Kem.decap(got.enc, skR);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &dec);
}

test "DHKEM X25519 deriveKeyPair: RFC 9180 A.1.1 skEm/pkEm from ikmE (and skRm/pkRm from ikmR), byte-exact" {
    const a1 = @import("kat_rfc9180.zig").a1;
    const kpE = X25519Kem.deriveKeyPair(&a1.ikmE);
    try testing.expectEqualSlices(u8, &a1.skEm, &kpE.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkEm, &kpE.public_key);
    const kpR = X25519Kem.deriveKeyPair(&a1.ikmR);
    try testing.expectEqualSlices(u8, &a1.skRm, &kpR.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkRm, &kpR.public_key);
}

test "DHKEM X25519 Encap: low-order pkR (all-zero DH output) fails closed with error.DhFailed" {
    // The all-zero public key is the canonical low-order input (RFC 7748
    // §6.1): scalarmult lands on the identity, which RFC 9180 §7.1.1
    // requires rejecting rather than deriving a predictable shared secret.
    const a1 = @import("kat_rfc9180.zig").a1;
    const low_order_pk = [_]u8{0} ** 32;
    const eph = X25519Kem.KeyPair{ .secret_key = a1.skEm, .public_key = a1.pkEm };
    try testing.expectError(error.DhFailed, X25519Kem.encapDeterministic(low_order_pk, eph));
    const skR = X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    try testing.expectError(error.DhFailed, X25519Kem.decap(low_order_pk, skR));
}

test "DHKEM X25519 AuthEncap/AuthDecap: self-consistency round trip + wrong-pkS divergence" {
    // The BYTE-EXACT anchor for this fold is `kat_rfc9180.zig`'s A.1.3/
    // A.1.4 vectors (and A.3.3/A.3.4 for P-256) — this test covers the
    // property those vectors cannot: that a WRONG sender public key
    // produces a different shared secret, i.e. the auth binding is load-
    // bearing rather than decorative. Round-trip agreement alone would
    // prove nothing about spec conformance (both sides could share one
    // misreading), which is exactly why the vectors came first.
    const skR = X25519Kem.deriveKeyPair("hpke auth-mode test receiver ikm");
    const skS = X25519Kem.deriveKeyPair("hpke auth-mode test sender ikm");
    const eph = X25519Kem.deriveKeyPair("hpke auth-mode test ephemeral ikm");
    const got = try X25519Kem.authEncapDeterministic(skR.public_key, skS, eph);
    try testing.expectEqualSlices(u8, &eph.public_key, &got.enc);
    const dec = try X25519Kem.authDecap(got.enc, skR, skS.public_key);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
    // A wrong sender key must NOT decap to the same secret (the auth
    // binding is real, not decorative).
    const wrong = X25519Kem.deriveKeyPair("hpke auth-mode test WRONG sender");
    const dec_wrong = try X25519Kem.authDecap(got.enc, skR, wrong.public_key);
    try testing.expect(!std.mem.eql(u8, &got.shared_secret, &dec_wrong));
}

test "DHKEM P-256 Encap/Decap: RFC 9180 A.3 enc/shared_secret, byte-exact" {
    const a3 = @import("kat_rfc9180.zig").a3;
    const eph = P256Kem.KeyPair{ .secret_key = a3.skEm, .public_key = a3.pkEm };
    const got = try P256Kem.encapDeterministic(a3.pkRm, eph);
    try testing.expectEqualSlices(u8, &a3.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a3.shared_secret, &got.shared_secret);
    const skR = P256Kem.KeyPair{ .secret_key = a3.skRm, .public_key = a3.pkRm };
    const dec = try P256Kem.decap(got.enc, skR);
    try testing.expectEqualSlices(u8, &a3.shared_secret, &dec);
}

test "DHKEM P-256 Encap/Decap: malformed SEC1 pkR fails closed with error.DeserializeError" {
    const a3 = @import("kat_rfc9180.zig").a3;
    const eph = P256Kem.KeyPair{ .secret_key = a3.skEm, .public_key = a3.pkEm };
    var bad = a3.pkRm;
    bad[0] = 0x05; // not a valid SEC1 tag
    try testing.expectError(error.DeserializeError, P256Kem.encapDeterministic(bad, eph));
    const skR = P256Kem.KeyPair{ .secret_key = a3.skRm, .public_key = a3.pkRm };
    try testing.expectError(error.DeserializeError, P256Kem.decap(bad, skR));
}

test "DHKEM P-256 deriveKeyPair: deterministic, on-curve, distinct per ikm (byte-exact anchor lives in the A.3.2/A.3.3/A.3.4 KATs)" {
    const kp1 = P256Kem.deriveKeyPair("hpke p256 derive test ikm 1");
    const kp1_again = P256Kem.deriveKeyPair("hpke p256 derive test ikm 1");
    try testing.expectEqualSlices(u8, &kp1.secret_key, &kp1_again.secret_key);
    try testing.expectEqualSlices(u8, &kp1.public_key, &kp1_again.public_key);
    const kp2 = P256Kem.deriveKeyPair("hpke p256 derive test ikm 2");
    try testing.expect(!std.mem.eql(u8, &kp1.secret_key, &kp2.secret_key));
    // public_key is a valid SEC1 point AND actually sk*G (Encap/Decap
    // round trip through it works).
    try testing.expectEqual(@as(u8, 0x04), kp1.public_key[0]);
    const eph = P256Kem.deriveKeyPair("hpke p256 derive test ephemeral");
    const got = try P256Kem.encapDeterministic(kp1.public_key, eph);
    const dec = try P256Kem.decap(got.enc, kp1);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
}

test "DHKEM P-256 AuthEncap/AuthDecap: self-consistency round trip" {
    const skR = P256Kem.deriveKeyPair("hpke p256 auth test receiver");
    const skS = P256Kem.deriveKeyPair("hpke p256 auth test sender");
    const eph = P256Kem.deriveKeyPair("hpke p256 auth test ephemeral");
    const got = try P256Kem.authEncapDeterministic(skR.public_key, skS, eph);
    const dec = try P256Kem.authDecap(got.enc, skR, skS.public_key);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
    const wrong = P256Kem.deriveKeyPair("hpke p256 auth test WRONG sender");
    const dec_wrong = try P256Kem.authDecap(got.enc, skR, wrong.public_key);
    try testing.expect(!std.mem.eql(u8, &got.shared_secret, &dec_wrong));
}

// ── fuzz: P256Kem.decap/authDecap never panic on arbitrary enc/pkS bytes ──
//
// `enc` (the sender's ephemeral public key) and, for auth mode, `pkS` are
// exactly the two DHKEM inputs a REMOTE PEER supplies on the wire — decap
// runs on them before any authentication has happened (there is no MAC or
// signature over the KEM ciphertext itself; the AEAD that follows is the
// only integrity check, and it authenticates the wrong thing to catch a
// malformed `enc`). Both are SEC1-encoded points (`P256.fromSec1`), so the
// harness biases the tag byte the same way `p256`'s own `fromSec1` fuzzer
// does. (X25519Kem's `enc`/`pkS` are raw 32-byte strings with no rejecting
// decode step at all — every bitstring is a valid input — so there is no
// analogous parser to fuzz there.)

test "fuzz: P256Kem.decap never panics on arbitrary enc bytes" {
    try testing.fuzz({}, fuzzP256Decap, .{});
}

fn fuzzedSec1Bytes(smith: *std.testing.Smith, buf: *[P256Kem.Npk]u8) void {
    smith.bytes(buf);
    buf[0] = switch (smith.valueRangeAtMost(u8, 0, 4)) {
        0 => 0,
        1 => 2,
        2 => 3,
        3 => 4,
        else => smith.value(u8),
    };
}

fn fuzzP256Decap(_: void, smith: *std.testing.Smith) !void {
    const skR = P256Kem.deriveKeyPair("hpke fuzz decap receiver");
    var enc: P256Kem.EncappedKey = undefined;
    fuzzedSec1Bytes(smith, &enc);
    _ = P256Kem.decap(enc, skR) catch {};
}

test "fuzz: P256Kem.authDecap never panics on arbitrary enc/pkS bytes" {
    try testing.fuzz({}, fuzzP256AuthDecap, .{});
}

fn fuzzP256AuthDecap(_: void, smith: *std.testing.Smith) !void {
    const skR = P256Kem.deriveKeyPair("hpke fuzz auth-decap receiver");
    var enc: P256Kem.EncappedKey = undefined;
    fuzzedSec1Bytes(smith, &enc);
    var pkS: P256Kem.PublicKey = undefined;
    fuzzedSec1Bytes(smith, &pkS);
    _ = P256Kem.authDecap(enc, skR, pkS) catch {};
}
