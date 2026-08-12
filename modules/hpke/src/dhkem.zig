// SPDX-License-Identifier: MIT
//! DHKEM (RFC 9180 §4 / §7.1) — the KEM half of HPKE: `Encap`/`Decap` (base
//! mode) and `AuthEncap`/`AuthDecap` (auth mode, §4.1 "Authentication using
//! Asymmetric Keys"), instantiated over the three DH groups this repo's std
//! toolchain can drive without a C dependency: X25519
//! (`dhkem_x25519_hkdf_sha256`), P-256 (`dhkem_p256_hkdf_sha256`) and P-384
//! (`dhkem_p384_hkdf_sha384`). Each DHKEM's internal KDF is FIXED per
//! `kem_id` (RFC 9180 §7.1 Table 2): HKDF-SHA256 for X25519/P-256,
//! HKDF-SHA384 for P-384 — independent of the outer ciphersuite's `kdf_id`
//! (`schedule.zig`'s `KdfOf`/`kdfIdOf`), which is why `extractAndExpand`
//! below takes the `Hkdf` type as a parameter rather than hardcoding one.
//!
//! **Everything here is REAL** (crypto-implementation pass done —
//! KAT-validated against RFC 9180 Appendix A.1/A.3, see `kat_rfc9180.zig`;
//! `AuthEncap`/`AuthDecap` and `P256Kem.deriveKeyPair` included, against
//! A.1.3/A.1.4 and A.3.3/A.3.4's published `enc`/`shared_secret` and
//! `ikmS`/`skSm`/`pkSm`). `P384Kem` is real and structurally identical to
//! `P256Kem` (same std composition, one curve group swapped for another),
//! but RFC 9180 Appendix A publishes NO worked test-vector section for
//! DHKEM(P-384, HKDF-SHA384) at all (unlike P-256/P-521/X25519, each of
//! which gets at least one) — see `P384Kem`'s doc comment and SPEC.md for
//! what anchors it instead.
//! `encapDeterministic`/`authEncapDeterministic` take the ephemeral keypair
//! as a parameter (rather than drawing one from `std.Io`'s randomness
//! internally) so the RFC 9180 Appendix A known-answer vectors — which fix
//! `skEm`/`pkEm` — can drive them byte-exact; `encap`/`authEncap` are thin
//! `generateKeyPair(io)` + `*Deterministic` wrappers for real callers.

const std = @import("std");
const suite = @import("suite.zig");
// Fail-closed entropy for the three `generateKeyPair`s below (CONVENTIONS.md
// §2.2). Nothing else in this module draws randomness: every other entry
// point either takes the ephemeral keypair as a parameter or derives from a
// caller-supplied `ikm`.
const entropy = @import("entropy");
// P-256 curve group for the DHKEM(P-256, …) suite from the asm-accelerated
// `p256` module (byte-exact to `std.crypto.ecc.P256`). The X25519 KEM path
// stays on std (p256 covers only the P-256 curve). P-384 has no local
// perf-specialized sibling (no stated hot path the way P-256's JWT/TLS/
// WebAuthn callers are, `modules/p256/README.md`'s "P2 HTTPS-API hot path"
// rationale), so `P384Kem` below is built directly on
// `std.crypto.ecc.P384` — same API shape as `p256`'s
// (`fromSec1`/`toUncompressedSec1`/`mul`/`affineCoordinates`/`scalar.
// random`/`scalar.rejectNonCanonical`), just not asm-accelerated.
const P256 = @import("p256").P256;
const P384 = std.crypto.ecc.P384;

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
// std names no `HkdfSha384` alias (unlike `HkdfSha256`/`HkdfSha512`) — same
// composition `schedule.zig`'s `KdfOf(48)` builds for the OUTER key-schedule
// KDF, reused here for `P384Kem`'s OWN internal KEM KDF (a separate choice,
// see this file's module doc comment) rather than importing `schedule.zig`
// (the higher layer) from here.
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

/// Errors an `Encap`/`AuthEncap` can return (RFC 9180 §4/§7.1 doesn't
/// itself name failure modes beyond "SerializeError"/"DeserializeError"
/// for malformed keys — X25519/P-256 DH can also reject a low-order/
/// identity result, RFC 9180 §7.1.4).
pub const EncapError = error{
    /// The DH computation hit the identity element / a low-order point
    /// (X25519 all-zero output, RFC 7748 §6.1; P-256 point-at-infinity) —
    /// RFC 9180 §7.1.4 calls this out as a required check, not an edge case
    /// to silently ignore: "senders and recipients MUST ensure the
    /// Diffie-Hellman shared secret is not the point at infinity". (§7.1.1 and
    /// §7.1.2, cited here before audit BD-26, are the serialization clauses
    /// and defer validation to §7.1.4.)
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
/// every KEM shares, PARAMETERIZED on that KEM's own internal `Hkdf`
/// (HKDF-SHA256 for X25519/P-256, HKDF-SHA384 for P-384 — RFC 9180 §7.1
/// Table 2, fixed per `kem_id`, independent of the outer ciphersuite's
/// `kdf_id`; see this file's module doc comment): `eae_prk =
/// LabeledExtract("", "eae_prk", dh)`; `shared_secret =
/// LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)` — both
/// under `kemSuiteId(kem_id)` ("KEM" || kem_id), NOT the outer HPKE
/// `suiteId` (which also folds in kdf_id/aead_id; §7.2.1 vs §4.1).
fn extractAndExpand(
    comptime Hkdf: type,
    comptime kem_id: u16,
    comptime Nsecret: usize,
    dh: []const u8,
    kem_context: []const u8,
) [Nsecret]u8 {
    const kem_suite_id = comptime suite.kemSuiteId(kem_id);
    const eae_prk = suite.labeledExtract(Hkdf, &kem_suite_id, "", "eae_prk", dh);
    var shared_secret: [Nsecret]u8 = undefined;
    // kem_context tops out at 291 bytes (P-384 auth mode: 3 × 97-byte SEC1
    // points) — far inside labeledExpand's 512-byte scratch, so
    // error.LabelTooLong is structurally unreachable here.
    suite.labeledExpand(Hkdf, &kem_suite_id, eae_prk, "shared_secret", kem_context, &shared_secret) catch unreachable;
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

    /// RFC 9180 §4's own definition, verbatim: `GenerateKeyPair() =
    /// DeriveKeyPair(random(Nsk))`. `entropy.fill` supplies `random(Nsk)`
    /// (CONVENTIONS.md §2.2) — every HPKE sender's ephemeral key is minted
    /// here, and this signature returns a `KeyPair`, not an error union, so
    /// a degraded seed would silently become the shared secret of every
    /// message the sender ever seals.
    ///
    /// Was `std.crypto.dh.X25519.KeyPair.generate(io)`, whose seed comes
    /// from `io.random` — the entry point with the silent-degrade clause.
    /// Routing through `deriveKeyPair` instead of open-coding std's
    /// retry loop also puts the KEYGEN path under this file's RFC 9180
    /// A.1.1 known-answer test, which `KeyPair.generate` never was.
    pub fn generateKeyPair(io: std.Io) KeyPair {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        return deriveKeyPair(&ikm);
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
            .shared_secret = extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context),
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
        return extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context);
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
            .shared_secret = extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context),
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
        return extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context);
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

    /// RFC 9180 §4's `GenerateKeyPair() = DeriveKeyPair(random(Nsk))`, with
    /// `entropy.fill` as `random` (CONVENTIONS.md §2.2).
    ///
    /// Was `P256.scalar.random(io, .big)`, which draws from `io.random`.
    /// The X25519 KEM above could have kept std's shape and swapped only
    /// the draw, because `KeyPair.generateDeterministic` is public; the
    /// NIST KEMs have no such twin — `scalar.random`'s rejection loop is
    /// std-internal and takes the `io` itself. Rather than re-implement
    /// that loop here, all three KEMs go through the RFC's own
    /// `DeriveKeyPair`, whose rejection sampling this file already owns
    /// and A.3.3 already pins.
    pub fn generateKeyPair(io: std.Io) KeyPair {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        return deriveKeyPair(&ikm);
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
            .shared_secret = extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context),
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
        return extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context);
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
            .shared_secret = extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context),
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
        return extractAndExpand(HkdfSha256, kem_id, Nsecret, &dh, &kem_context);
    }
};

// ── DHKEM(P-384, HKDF-SHA384) — RFC 9180 §7.1, kem_id 0x0011 ────────────

/// `dhkem_p384_hkdf_sha384` (RFC 9180 §7.1 Table 2): Nsecret = 48
/// (HKDF-SHA384's `Nh`), Nsk = 48 (a P-384 scalar), Npk = 97 (SEC1
/// UNCOMPRESSED point encoding — `0x04 || X(48) || Y(48)`, same convention
/// as `P256Kem`). Structurally this is `P256Kem` with the curve group and
/// internal KDF both swapped: `std.crypto.ecc.P384` in place of
/// `p256`'s `P256` (`fromSec1`/`toUncompressedSec1`/`mul`/
/// `affineCoordinates`/`scalar.random`/`scalar.rejectNonCanonical` — the
/// identical API shape, see this file's module doc comment for why P-384
/// stays on std rather than getting its own asm-accelerated sibling
/// module), and `HkdfSha384` in place of `HkdfSha256` for
/// `extractAndExpand`/`deriveKeyPair`'s internal KDF (RFC 9180 §7.1 Table 2
/// fixes DHKEM(P-384, …)'s own KDF to HKDF-SHA384 — NOT the HKDF-SHA256
/// every other KEM this module instantiates uses internally; this is
/// exactly the "DHKEM's own KDF is a separate choice from the outer
/// ciphersuite's kdf_id" distinction `schedule.zig`'s module doc comment
/// describes, now demonstrated by a KEM whose OWN choice differs from
/// HKDF-SHA256 for the first time, not just the outer key schedule's).
///
/// **No RFC 9180 Appendix A byte-exact anchor exists for this KEM** — see
/// this struct's tests and SPEC.md's done-record for what anchors it
/// instead (type widths against §7.1 Table 2's own definitional text,
/// self-consistency round trips, and low-order/malformed-SEC1 rejection —
/// the same class of test `P256Kem`'s own non-KAT-covered surfaces, e.g.
/// its `basePoint.mul + toUncompressedSec1` smoke test, already rely on).
pub const P384Kem = struct {
    pub const kem_id: u16 = @intFromEnum(suite.KemId.dhkem_p384_hkdf_sha384);
    pub const Nsecret: usize = 48;
    pub const Npk: usize = 97; // SEC1 uncompressed: 0x04 || X(48) || Y(48)
    pub const Nsk: usize = 48;

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

    /// Same composition as `P256Kem.generateKeyPair` — RFC 9180 §4's
    /// `DeriveKeyPair(random(Nsk))` over `entropy.fill`, replacing
    /// `P384.scalar.random(io, .big)`. This KEM has no published Appendix A
    /// vector (see this type's doc comment), so unlike its two siblings the
    /// keygen path here gains no external anchor from the move — only the
    /// fail-closed draw and one shape across all three KEMs.
    pub fn generateKeyPair(io: std.Io) KeyPair {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        return deriveKeyPair(&ikm);
    }

    /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for P-384 — the same
    /// rejection-sampling loop as `P256Kem.deriveKeyPair`, over
    /// `HkdfSha384` (this KEM's own internal KDF, not `HkdfSha256`) and
    /// `Nsk=48`. `bitmask = 0xFF` (RFC 9180 §7.1.3: 0xFF for every curve
    /// except P-521, which needs 0x01 to narrow a 528-bit encoding down to
    /// P-521's 521-bit order — P-384's Nsk=48 bytes = 384 bits already
    /// matches its order's bit length, same reasoning as P-256).
    pub fn deriveKeyPair(ikm: []const u8) KeyPair {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        const dkp_prk = suite.labeledExtract(HkdfSha384, &kem_suite_id, "", "dkp_prk", ikm);
        var counter: u16 = 0;
        while (counter <= 255) : (counter += 1) {
            const ctr = suite.i2osp(1, counter);
            var candidate: [Nsk]u8 = undefined;
            suite.labeledExpand(HkdfSha384, &kem_suite_id, dkp_prk, "candidate", &ctr, &candidate) catch unreachable;
            candidate[0] &= 0xff; // RFC 9180 §7.1.3 bitmask (0xFF for P-384)
            P384.scalar.rejectNonCanonical(candidate, .big) catch continue; // sk >= n
            if (std.mem.allEqual(u8, &candidate, 0)) continue; // sk == 0
            // basePoint * nonzero canonical scalar never hits the identity.
            const pk_point = P384.basePoint.mul(candidate, .big) catch unreachable;
            return .{ .secret_key = candidate, .public_key = pk_point.toUncompressedSec1() };
        }
        @panic("hpke: P-384 DeriveKeyPair exhausted 256 candidates (probability ~2^-8192; RFC 9180 7.1.3 DeriveKeyPairError)");
    }

    /// RFC 9180 §4.1/§7.1.2 `Encap(pkR)` for P-384 — same shape as
    /// `P256Kem.encapDeterministic`: x-coordinate-only ECDH, `Nsecret=48`
    /// via `HkdfSha384`.
    pub fn encapDeterministic(pkR: PublicKey, eph: KeyPair) EncapError!Encapped {
        const pkR_point = P384.fromSec1(&pkR) catch return error.DeserializeError;
        const shared_point = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR;
        return .{
            .shared_secret = extractAndExpand(HkdfSha384, kem_id, Nsecret, &dh, &kem_context),
            .enc = eph.public_key,
        };
    }

    pub fn encap(pkR: PublicKey, io: std.Io) EncapError!Encapped {
        return encapDeterministic(pkR, generateKeyPair(io));
    }

    /// Mirror of `encapDeterministic`.
    pub fn decap(enc: EncappedKey, skR: KeyPair) DecapError![Nsecret]u8 {
        const enc_point = P384.fromSec1(&enc) catch return error.DeserializeError;
        const shared_point = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc;
        kem_context[Npk..].* = skR.public_key;
        return extractAndExpand(HkdfSha384, kem_id, Nsecret, &dh, &kem_context);
    }

    /// RFC 9180 §4.1 `AuthEncap(pkR, skS)` for P-384 — same `dh || dh2`
    /// fold as `P256Kem.authEncapDeterministic`.
    pub fn authEncapDeterministic(pkR: PublicKey, skS: KeyPair, eph: KeyPair) EncapError!Encapped {
        const pkR_point = P384.fromSec1(&pkR) catch return error.DeserializeError;
        var dh: [2 * Nsk]u8 = undefined;
        const p1 = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        dh[0..Nsk].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkR_point.mul(skS.secret_key, .big) catch return error.DhFailed;
        dh[Nsk..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR;
        kem_context[2 * Npk ..].* = skS.public_key;
        return .{
            .shared_secret = extractAndExpand(HkdfSha384, kem_id, Nsecret, &dh, &kem_context),
            .enc = eph.public_key,
        };
    }

    pub fn authDecap(enc: EncappedKey, skR: KeyPair, pkS: PublicKey) DecapError![Nsecret]u8 {
        const enc_point = P384.fromSec1(&enc) catch return error.DeserializeError;
        const pkS_point = P384.fromSec1(&pkS) catch return error.DeserializeError;
        var dh: [2 * Nsk]u8 = undefined;
        const p1 = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[0..Nsk].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkS_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[Nsk..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS;
        return extractAndExpand(HkdfSha384, kem_id, Nsecret, &dh, &kem_context);
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

// ── DHKEM P-384 — no RFC 9180 Appendix A vector exists for this KEM (see
// `P384Kem`'s doc comment); the tests below are the same class of anchor
// `P256Kem`'s own non-KAT surfaces already rely on: type widths against
// §7.1 Table 2's definitional text, a pure-math basePoint smoke test,
// self-consistency round trips (Encap/Decap, AuthEncap/AuthDecap,
// DeriveKeyPair determinism), and low-order/malformed-SEC1 rejection.

test "P384Kem: type widths match RFC 9180 Table 2 (SEC1 uncompressed Npk=97)" {
    try testing.expectEqual(@as(usize, 48), P384Kem.Nsecret);
    try testing.expectEqual(@as(usize, 97), P384Kem.Npk);
    try testing.expectEqual(@as(usize, 48), P384Kem.Nsk);
    try testing.expectEqual(@as(u16, 0x0011), P384Kem.kem_id);
}

test "P384Kem: basePoint.mul + toUncompressedSec1 wiring produces a well-formed SEC1 point" {
    // Mirrors P256Kem's analogous smoke test: scalar = 1 -> pk == the
    // curve's own basePoint, uncompressed-encoded.
    const one = [_]u8{0} ** 47 ++ [_]u8{1};
    const pk_point = P384.basePoint.mul(one, .big) catch unreachable;
    const pk = pk_point.toUncompressedSec1();
    try testing.expectEqual(@as(u8, 0x04), pk[0]); // SEC1 uncompressed tag
    try testing.expectEqual(@as(usize, 97), pk.len);
    try testing.expect(pk_point.equivalent(P384.basePoint));
}

test "DHKEM P-384 Encap/Decap: self-consistency round trip" {
    const skR = P384Kem.deriveKeyPair("hpke p384 test receiver");
    const eph = P384Kem.deriveKeyPair("hpke p384 test ephemeral");
    const got = try P384Kem.encapDeterministic(skR.public_key, eph);
    try testing.expectEqualSlices(u8, &eph.public_key, &got.enc);
    const dec = try P384Kem.decap(got.enc, skR);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
}

test "DHKEM P-384 Encap/Decap: malformed SEC1 pkR fails closed with error.DeserializeError" {
    const skR = P384Kem.deriveKeyPair("hpke p384 test receiver 3");
    const eph = P384Kem.deriveKeyPair("hpke p384 test ephemeral 3");
    var bad: P384Kem.PublicKey = undefined;
    bad[0] = 0x05; // not a valid SEC1 tag
    try testing.expectError(error.DeserializeError, P384Kem.encapDeterministic(bad, eph));
    try testing.expectError(error.DeserializeError, P384Kem.decap(bad, skR));
}

test "DHKEM P-384 deriveKeyPair: deterministic, on-curve, distinct per ikm" {
    const kp1 = P384Kem.deriveKeyPair("hpke p384 derive test ikm 1");
    const kp1_again = P384Kem.deriveKeyPair("hpke p384 derive test ikm 1");
    try testing.expectEqualSlices(u8, &kp1.secret_key, &kp1_again.secret_key);
    try testing.expectEqualSlices(u8, &kp1.public_key, &kp1_again.public_key);
    const kp2 = P384Kem.deriveKeyPair("hpke p384 derive test ikm 2");
    try testing.expect(!std.mem.eql(u8, &kp1.secret_key, &kp2.secret_key));
    try testing.expectEqual(@as(u8, 0x04), kp1.public_key[0]);
    // public_key is actually sk*G: Encap/Decap round trip through it works.
    const eph = P384Kem.deriveKeyPair("hpke p384 derive test ephemeral");
    const got = try P384Kem.encapDeterministic(kp1.public_key, eph);
    const dec = try P384Kem.decap(got.enc, kp1);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
}

test "DHKEM P-384 AuthEncap/AuthDecap: self-consistency round trip + wrong-pkS divergence" {
    const skR = P384Kem.deriveKeyPair("hpke p384 auth test receiver");
    const skS = P384Kem.deriveKeyPair("hpke p384 auth test sender");
    const eph = P384Kem.deriveKeyPair("hpke p384 auth test ephemeral");
    const got = try P384Kem.authEncapDeterministic(skR.public_key, skS, eph);
    const dec = try P384Kem.authDecap(got.enc, skR, skS.public_key);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
    const wrong = P384Kem.deriveKeyPair("hpke p384 auth test WRONG sender");
    const dec_wrong = try P384Kem.authDecap(got.enc, skR, wrong.public_key);
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

// Generic over the SEC1-encoded width (comptime N) so P384Kem's fuzz
// harness below can reuse it verbatim at Npk=97 rather than duplicating
// the byte-biasing recipe.
fn fuzzedSec1Bytes(comptime N: usize, smith: *std.testing.Smith, buf: *[N]u8) void {
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
    fuzzedSec1Bytes(P256Kem.Npk, smith, &enc);
    _ = P256Kem.decap(enc, skR) catch {};
}

test "fuzz: P256Kem.authDecap never panics on arbitrary enc/pkS bytes" {
    try testing.fuzz({}, fuzzP256AuthDecap, .{});
}

fn fuzzP256AuthDecap(_: void, smith: *std.testing.Smith) !void {
    const skR = P256Kem.deriveKeyPair("hpke fuzz auth-decap receiver");
    var enc: P256Kem.EncappedKey = undefined;
    fuzzedSec1Bytes(P256Kem.Npk, smith, &enc);
    var pkS: P256Kem.PublicKey = undefined;
    fuzzedSec1Bytes(P256Kem.Npk, smith, &pkS);
    _ = P256Kem.authDecap(enc, skR, pkS) catch {};
}

// ── fuzz: P384Kem.decap/authDecap never panic on arbitrary enc/pkS bytes ──
// Same rationale as the P256Kem fuzz harness above — `enc`/`pkS` are
// attacker-controlled wire bytes decap must never panic on, and P384Kem's
// `fromSec1` is the analogous rejecting-decode step X25519Kem lacks.

test "fuzz: P384Kem.decap never panics on arbitrary enc bytes" {
    try testing.fuzz({}, fuzzP384Decap, .{});
}

fn fuzzP384Decap(_: void, smith: *std.testing.Smith) !void {
    const skR = P384Kem.deriveKeyPair("hpke fuzz p384 decap receiver");
    var enc: P384Kem.EncappedKey = undefined;
    fuzzedSec1Bytes(P384Kem.Npk, smith, &enc);
    _ = P384Kem.decap(enc, skR) catch {};
}

test "fuzz: P384Kem.authDecap never panics on arbitrary enc/pkS bytes" {
    try testing.fuzz({}, fuzzP384AuthDecap, .{});
}

fn fuzzP384AuthDecap(_: void, smith: *std.testing.Smith) !void {
    const skR = P384Kem.deriveKeyPair("hpke fuzz p384 auth-decap receiver");
    var enc: P384Kem.EncappedKey = undefined;
    fuzzedSec1Bytes(P384Kem.Npk, smith, &enc);
    var pkS: P384Kem.PublicKey = undefined;
    fuzzedSec1Bytes(P384Kem.Npk, smith, &pkS);
    _ = P384Kem.authDecap(enc, skR, pkS) catch {};
}

// `P384Kem` has no RFC 9180 Appendix A vector (see SPEC.md item 16), so every
// other test it has is self-consistent: encap and decap run the same code, and
// a mutation applied to BOTH of them stays invisible. That is not theoretical
// — swapping `HkdfSha384` for `HkdfSha512` here leaves the entire suite green
// while making the module wire-incompatible with every other HPKE
// implementation on earth.
//
// The width checks below are NOT sufficient on their own, and the re-audit of
// 2026-08-11 proved it by measurement: `Nsecret` is a separately-declared
// constant that `extractAndExpand` takes as its own comptime parameter, and
// `labeledExpand` expands to whatever length it is asked for — so swapping this
// KEM's `HkdfSha384` for `HkdfSha256` (or `HkdfSha512`) still yields a 48-byte
// `shared_secret`, leaves `HkdfSha384.prk_length == 48` true (that is a property
// of the alias, not of what `P384Kem` calls), and left `test-hpke` at exit 0.
// The width test is kept because it does pin `Npk`/`Nsk`/`kem_id`, but the
// derivation test below is what actually discriminates the hash.
test "P384Kem: type widths and PRK width match RFC 9180 §7.1 Table 2" {
    try std.testing.expectEqual(@as(usize, 48), HkdfSha384.prk_length);
    try std.testing.expectEqual(@as(usize, 48), P384Kem.Nsecret);
    // The sibling KEMs' internal KDF is HKDF-SHA256 (same table), so the same
    // check pins them against a P-384-shaped copy-paste in either direction.
    try std.testing.expectEqual(@as(usize, 32), HkdfSha256.prk_length);
}

// The discriminating test. `P384Kem` has no RFC 9180 Appendix A vector (see
// SPEC.md done-record item 16), so every OTHER test it has is self-consistent:
// `encap` and `decap` run the same code, and a mutation applied to both stays
// invisible. A wrong internal KDF is exactly that shape of defect — and it is
// not cosmetic, it makes the module wire-incompatible with every other HPKE
// implementation while every round trip still agrees with itself.
//
// This test breaks the self-reference by recomputing `shared_secret` from the
// RFC's own §4.1/§7.1.2 recipe through an INDEPENDENT path: `std`'s one-shot
// `Hkdf.extract`/`.expand` over hand-concatenated labeled buffers, rather than
// `suite.labeledExtract`'s streaming HMAC that the implementation uses. Both
// the hash choice and the labeled-input layout have to agree for it to pass.
test "P384Kem's internal KDF is HKDF-SHA384: shared_secret matches an independent labeled-HKDF derivation" {
    const skR = P384Kem.deriveKeyPair("hpke p384 kdf-discriminator receiver");
    const eph = P384Kem.deriveKeyPair("hpke p384 kdf-discriminator ephemeral");
    const got = try P384Kem.encapDeterministic(skR.public_key, eph);

    // dh, recomputed here from the curve rather than taken from the KEM.
    const shared_point = try (try P384.fromSec1(&skR.public_key)).mul(eph.secret_key, .big);
    const dh = shared_point.affineCoordinates().x.toBytes(.big);

    const kem_suite_id = suite.kemSuiteId(0x0011); // "KEM" || I2OSP(0x0011, 2)

    // eae_prk = LabeledExtract("", "eae_prk", dh), concatenated not streamed.
    var ikm: [7 + 5 + 7 + 48]u8 = undefined;
    @memcpy(ikm[0..7], "HPKE-v1");
    @memcpy(ikm[7..12], &kem_suite_id);
    @memcpy(ikm[12..19], "eae_prk");
    @memcpy(ikm[19..], &dh);
    const eae_prk = HkdfSha384.extract("", &ikm);

    // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, 48)
    var info: [2 + 7 + 5 + 13 + 2 * P384Kem.Npk]u8 = undefined;
    std.mem.writeInt(u16, info[0..2], 48, .big); // I2OSP(L, 2)
    @memcpy(info[2..9], "HPKE-v1");
    @memcpy(info[9..14], &kem_suite_id);
    @memcpy(info[14..27], "shared_secret");
    @memcpy(info[27 .. 27 + P384Kem.Npk], &eph.public_key);
    @memcpy(info[27 + P384Kem.Npk ..], &skR.public_key);
    var want: [48]u8 = undefined;
    HkdfSha384.expand(&want, &info, eae_prk);

    try testing.expectEqualSlices(u8, &want, &got.shared_secret);
}
