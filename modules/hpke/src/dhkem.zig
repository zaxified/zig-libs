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
const burn = @import("burn.zig");
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
// P-521 (std has none): the `p521` module — constant-time `ecdhInto` for
// every DH with a secret scalar, `mulInto` for the key derivation.
const p521 = @import("p521");
const HkdfSha512 = std.crypto.kdf.hkdf.HkdfSha512;

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
    out: *[Nsecret]u8,
    dh: []const u8,
    kem_context: []const u8,
) void {
    const kem_suite_id = comptime suite.kemSuiteId(kem_id);
    var eae_prk: [Hkdf.prk_length]u8 = undefined;
    suite.labeledExtract(Hkdf, &eae_prk, &kem_suite_id, "", "eae_prk", dh);
    // kem_context tops out at 399 bytes (P-521 auth mode: 3 × 133-byte SEC1
    // points); with the 7-byte "HPKE-v1", the 5-byte suite id, the
    // 13-byte label and the 2-byte length that is 426 bytes, inside
    // labeledExpand's 512-byte scratch, so error.LabelTooLong is
    // structurally unreachable here.
    suite.labeledExpand(Hkdf, &kem_suite_id, &eae_prk, "shared_secret", kem_context, out) catch unreachable;
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
    pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        deriveKeyPair(out, &ikm);
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
    pub fn deriveKeyPair(out: *KeyPair, ikm: []const u8) void {
        burn.run(burn.kem_burn, void, deriveKeyPairBody, .{ out, ikm });
    }

    fn deriveKeyPairBody(out: *KeyPair, ikm: []const u8) void {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        var dkp_prk: [HkdfSha256.prk_length]u8 = undefined;
        suite.labeledExtract(HkdfSha256, &dkp_prk, &kem_suite_id, "", "dkp_prk", ikm);
        var sk: [Nsk]u8 = undefined;
        // Empty info + tiny label: LabelTooLong structurally unreachable.
        suite.labeledExpand(HkdfSha256, &kem_suite_id, &dkp_prk, "sk", "", &sk) catch unreachable;
        // A clamped X25519 scalar (high bit pattern forced by RFC 7748
        // clamping) times the basepoint can never land on the identity, so
        // generateDeterministic's IdentityElementError is unreachable.
        out.* = KeyPair.generateDeterministic(sk) catch unreachable;
    }

    /// RFC 9180 §4.1 `Encap(pkR)`, real-randomness entry point: draw a
    /// fresh ephemeral keypair via `io`, then defer to
    /// `encapDeterministic`.
    pub fn encap(out: *Encapped, pkR: PublicKey, io: std.Io) EncapError!void {
        var eph: KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&eph));
        generateKeyPair(&eph, io);
        return encapDeterministic(out, pkR, &eph);
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
    pub fn encapDeterministic(out: *Encapped, pkR: PublicKey, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, encapBody, .{ out, &pkR, eph });
    }

    fn encapBody(out: *Encapped, pkR: *const PublicKey, eph: *const KeyPair) EncapError!void {
        const dh = std.crypto.dh.X25519.scalarmult(eph.secret_key, pkR.*) catch return error.DhFailed;
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR.*;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, &out.shared_secret, &dh, &kem_context);
        out.enc = eph.public_key;
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
    pub fn decap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, decapBody, .{ out, &enc, skR });
    }

    fn decapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair) DecapError!void {
        const dh = std.crypto.dh.X25519.scalarmult(skR.secret_key, enc.*) catch return error.DhFailed;
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk..].* = skR.public_key;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, out, &dh, &kem_context);
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
    pub fn authEncapDeterministic(out: *Encapped, pkR: PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, authEncapBody, .{ out, &pkR, skS, eph });
    }

    fn authEncapBody(out: *Encapped, pkR: *const PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        var dh: [64]u8 = undefined;
        dh[0..32].* = std.crypto.dh.X25519.scalarmult(eph.secret_key, pkR.*) catch return error.DhFailed;
        dh[32..].* = std.crypto.dh.X25519.scalarmult(skS.secret_key, pkR.*) catch return error.DhFailed;
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR.*;
        kem_context[2 * Npk ..].* = skS.public_key;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, &out.shared_secret, &dh, &kem_context);
        out.enc = eph.public_key;
    }

    /// RFC 9180 §4.1 `AuthDecap(enc, skR, pkS)` — the mirror:
    /// ```text
    /// pkE = enc
    /// dh  = DH(skR, pkE)
    /// dh2 = DH(skR, pkS)
    /// kem_context = enc || pk(skR) || pkS
    /// shared_secret = ExtractAndExpand(dh || dh2, kem_context)
    /// ```
    pub fn authDecap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair, pkS: PublicKey) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, authDecapBody, .{ out, &enc, skR, &pkS });
    }

    fn authDecapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair, pkS: *const PublicKey) DecapError!void {
        var dh: [64]u8 = undefined;
        dh[0..32].* = std.crypto.dh.X25519.scalarmult(skR.secret_key, enc.*) catch return error.DhFailed;
        dh[32..].* = std.crypto.dh.X25519.scalarmult(skR.secret_key, pkS.*) catch return error.DhFailed;
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS.*;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, out, &dh, &kem_context);
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
    pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        deriveKeyPair(out, &ikm);
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
    pub fn deriveKeyPair(out: *KeyPair, ikm: []const u8) void {
        burn.run(burn.kem_burn, void, deriveKeyPairBody, .{ out, ikm });
    }

    fn deriveKeyPairBody(out: *KeyPair, ikm: []const u8) void {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        var dkp_prk: [HkdfSha256.prk_length]u8 = undefined;
        suite.labeledExtract(HkdfSha256, &dkp_prk, &kem_suite_id, "", "dkp_prk", ikm);
        var counter: u16 = 0;
        while (counter <= 255) : (counter += 1) {
            const ctr = suite.i2osp(1, counter);
            var candidate: [Nsk]u8 = undefined;
            suite.labeledExpand(HkdfSha256, &kem_suite_id, &dkp_prk, "candidate", &ctr, &candidate) catch unreachable;
            candidate[0] &= 0xff; // RFC 9180 §7.1.3 bitmask (0xFF for P-256)
            P256.scalar.rejectNonCanonical(candidate, .big) catch continue; // sk >= n
            if (std.mem.allEqual(u8, &candidate, 0)) continue; // sk == 0
            // basePoint * nonzero canonical scalar never hits the identity.
            const pk_point = P256.basePoint.mul(candidate, .big) catch unreachable;
            out.* = .{ .secret_key = candidate, .public_key = pk_point.toUncompressedSec1() };
            return;
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
    pub fn encapDeterministic(out: *Encapped, pkR: PublicKey, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, encapBody, .{ out, &pkR, eph });
    }

    fn encapBody(out: *Encapped, pkR: *const PublicKey, eph: *const KeyPair) EncapError!void {
        const pkR_point = P256.fromSec1(pkR) catch return error.DeserializeError;
        const shared_point = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR.*;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, &out.shared_secret, &dh, &kem_context);
        out.enc = eph.public_key;
    }

    pub fn encap(out: *Encapped, pkR: PublicKey, io: std.Io) EncapError!void {
        var eph: KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&eph));
        generateKeyPair(&eph, io);
        return encapDeterministic(out, pkR, &eph);
    }

    /// Mirror of `encapDeterministic`: `dh = P256.fromSec1(&enc).mul(skR.secret_key,
    /// .big).affineCoordinates().x.toBytes(.big)`; `kem_context = enc ||
    /// skR.public_key`.
    pub fn decap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, decapBody, .{ out, &enc, skR });
    }

    fn decapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair) DecapError!void {
        const enc_point = P256.fromSec1(enc) catch return error.DeserializeError;
        const shared_point = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk..].* = skR.public_key;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, out, &dh, &kem_context);
    }

    /// RFC 9180 §4.1 `AuthEncap(pkR, skS)` for P-256 — same `dh || dh2`
    /// fold as `X25519Kem.authEncapDeterministic`, with each `dh`/`dh2`
    /// being the 32-byte X coordinate (not the raw scalarmult output).
    pub fn authEncapDeterministic(out: *Encapped, pkR: PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, authEncapBody, .{ out, &pkR, skS, eph });
    }

    fn authEncapBody(out: *Encapped, pkR: *const PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        const pkR_point = P256.fromSec1(pkR) catch return error.DeserializeError;
        var dh: [64]u8 = undefined;
        const p1 = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        dh[0..32].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkR_point.mul(skS.secret_key, .big) catch return error.DhFailed;
        dh[32..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR.*;
        kem_context[2 * Npk ..].* = skS.public_key;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, &out.shared_secret, &dh, &kem_context);
        out.enc = eph.public_key;
    }

    pub fn authDecap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair, pkS: PublicKey) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, authDecapBody, .{ out, &enc, skR, &pkS });
    }

    fn authDecapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair, pkS: *const PublicKey) DecapError!void {
        const enc_point = P256.fromSec1(enc) catch return error.DeserializeError;
        const pkS_point = P256.fromSec1(pkS) catch return error.DeserializeError;
        var dh: [64]u8 = undefined;
        const p1 = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[0..32].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkS_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[32..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS.*;
        extractAndExpand(HkdfSha256, kem_id, Nsecret, out, &dh, &kem_context);
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
    pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        deriveKeyPair(out, &ikm);
    }

    /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for P-384 — the same
    /// rejection-sampling loop as `P256Kem.deriveKeyPair`, over
    /// `HkdfSha384` (this KEM's own internal KDF, not `HkdfSha256`) and
    /// `Nsk=48`. `bitmask = 0xFF` (RFC 9180 §7.1.3: 0xFF for every curve
    /// except P-521, which needs 0x01 to narrow a 528-bit encoding down to
    /// P-521's 521-bit order — P-384's Nsk=48 bytes = 384 bits already
    /// matches its order's bit length, same reasoning as P-256).
    pub fn deriveKeyPair(out: *KeyPair, ikm: []const u8) void {
        burn.run(burn.kem_burn, void, deriveKeyPairBody, .{ out, ikm });
    }

    fn deriveKeyPairBody(out: *KeyPair, ikm: []const u8) void {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        var dkp_prk: [HkdfSha384.prk_length]u8 = undefined;
        suite.labeledExtract(HkdfSha384, &dkp_prk, &kem_suite_id, "", "dkp_prk", ikm);
        var counter: u16 = 0;
        while (counter <= 255) : (counter += 1) {
            const ctr = suite.i2osp(1, counter);
            var candidate: [Nsk]u8 = undefined;
            suite.labeledExpand(HkdfSha384, &kem_suite_id, &dkp_prk, "candidate", &ctr, &candidate) catch unreachable;
            candidate[0] &= 0xff; // RFC 9180 §7.1.3 bitmask (0xFF for P-384)
            P384.scalar.rejectNonCanonical(candidate, .big) catch continue; // sk >= n
            if (std.mem.allEqual(u8, &candidate, 0)) continue; // sk == 0
            // basePoint * nonzero canonical scalar never hits the identity.
            const pk_point = P384.basePoint.mul(candidate, .big) catch unreachable;
            out.* = .{ .secret_key = candidate, .public_key = pk_point.toUncompressedSec1() };
            return;
        }
        @panic("hpke: P-384 DeriveKeyPair exhausted 256 candidates (probability ~2^-8192; RFC 9180 7.1.3 DeriveKeyPairError)");
    }

    /// RFC 9180 §4.1/§7.1.2 `Encap(pkR)` for P-384 — same shape as
    /// `P256Kem.encapDeterministic`: x-coordinate-only ECDH, `Nsecret=48`
    /// via `HkdfSha384`.
    pub fn encapDeterministic(out: *Encapped, pkR: PublicKey, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, encapBody, .{ out, &pkR, eph });
    }

    fn encapBody(out: *Encapped, pkR: *const PublicKey, eph: *const KeyPair) EncapError!void {
        const pkR_point = P384.fromSec1(pkR) catch return error.DeserializeError;
        const shared_point = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR.*;
        extractAndExpand(HkdfSha384, kem_id, Nsecret, &out.shared_secret, &dh, &kem_context);
        out.enc = eph.public_key;
    }

    pub fn encap(out: *Encapped, pkR: PublicKey, io: std.Io) EncapError!void {
        var eph: KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&eph));
        generateKeyPair(&eph, io);
        return encapDeterministic(out, pkR, &eph);
    }

    /// Mirror of `encapDeterministic`.
    pub fn decap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, decapBody, .{ out, &enc, skR });
    }

    fn decapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair) DecapError!void {
        const enc_point = P384.fromSec1(enc) catch return error.DeserializeError;
        const shared_point = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        const dh = shared_point.affineCoordinates().x.toBytes(.big);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk..].* = skR.public_key;
        extractAndExpand(HkdfSha384, kem_id, Nsecret, out, &dh, &kem_context);
    }

    /// RFC 9180 §4.1 `AuthEncap(pkR, skS)` for P-384 — same `dh || dh2`
    /// fold as `P256Kem.authEncapDeterministic`.
    pub fn authEncapDeterministic(out: *Encapped, pkR: PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, authEncapBody, .{ out, &pkR, skS, eph });
    }

    fn authEncapBody(out: *Encapped, pkR: *const PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        const pkR_point = P384.fromSec1(pkR) catch return error.DeserializeError;
        var dh: [2 * Nsk]u8 = undefined;
        const p1 = pkR_point.mul(eph.secret_key, .big) catch return error.DhFailed;
        dh[0..Nsk].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkR_point.mul(skS.secret_key, .big) catch return error.DhFailed;
        dh[Nsk..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR.*;
        kem_context[2 * Npk ..].* = skS.public_key;
        extractAndExpand(HkdfSha384, kem_id, Nsecret, &out.shared_secret, &dh, &kem_context);
        out.enc = eph.public_key;
    }

    pub fn authDecap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair, pkS: PublicKey) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, authDecapBody, .{ out, &enc, skR, &pkS });
    }

    fn authDecapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair, pkS: *const PublicKey) DecapError!void {
        const enc_point = P384.fromSec1(enc) catch return error.DeserializeError;
        const pkS_point = P384.fromSec1(pkS) catch return error.DeserializeError;
        var dh: [2 * Nsk]u8 = undefined;
        const p1 = enc_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[0..Nsk].* = p1.affineCoordinates().x.toBytes(.big);
        const p2 = pkS_point.mul(skR.secret_key, .big) catch return error.DhFailed;
        dh[Nsk..].* = p2.affineCoordinates().x.toBytes(.big);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS.*;
        extractAndExpand(HkdfSha384, kem_id, Nsecret, out, &dh, &kem_context);
    }
};

// ── DHKEM(P-521, HKDF-SHA512) — RFC 9180 §7.1, kem_id 0x0012 ────────────

/// `dhkem_p521_hkdf_sha512` (RFC 9180 §7.1 Table 2): Nsecret = 64
/// (HKDF-SHA512's `Nh`), Nsk = 66, Npk = 133 (SEC1 uncompressed,
/// `0x04 || X(66) || Y(66)`). The group is the in-repo `p521` module (std
/// has no P-521): every DH runs through `p521.ecdhInto` — constant time in
/// the scalar, peer point validated (canonical, on the curve, not the
/// identity), result's identity refused. `DeriveKeyPair` uses the 0x01
/// bitmask §7.1.3 gives P-521 (Nsk = 66 bytes = 528 bits, the order has
/// 521). Anchored byte-exact to RFC 9180 A.6 (all four modes,
/// `kat_rfc9180_a6.zig`).
pub const P521Kem = struct {
    pub const kem_id: u16 = @intFromEnum(suite.KemId.dhkem_p521_hkdf_sha512);
    pub const Nsecret: usize = 64;
    pub const Npk: usize = 133; // SEC1 uncompressed: 0x04 || X(66) || Y(66)
    pub const Nsk: usize = 66;

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

    /// RFC 9180 §4 `DeriveKeyPair(random(Nsk))` over `entropy.fill`, as the
    /// other two NIST KEMs.
    pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
        var ikm: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &ikm);
        entropy.fill(io, &ikm);
        deriveKeyPair(out, &ikm);
    }

    /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for P-521: candidates from
    /// `LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), 66)` with
    /// `bitmask = 0x01` on the first byte, the first one in [1, n − 1].
    /// KAT: A.6.1–A.6.4's ikmE/ikmR/ikmS → skXm/pkXm.
    pub fn deriveKeyPair(out: *KeyPair, ikm: []const u8) void {
        burn.run(burn.kem_burn, void, deriveKeyPairBody, .{ out, ikm });
    }

    fn deriveKeyPairBody(out: *KeyPair, ikm: []const u8) void {
        const kem_suite_id = comptime suite.kemSuiteId(kem_id);
        var dkp_prk: [HkdfSha512.prk_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &dkp_prk);
        suite.labeledExtract(HkdfSha512, &dkp_prk, &kem_suite_id, "", "dkp_prk", ikm);
        var counter: u16 = 0;
        while (counter <= 255) : (counter += 1) {
            const ctr = suite.i2osp(1, counter);
            var candidate: [Nsk]u8 = undefined;
            suite.labeledExpand(HkdfSha512, &kem_suite_id, &dkp_prk, "candidate", &ctr, &candidate) catch unreachable;
            candidate[0] &= 0x01; // RFC 9180 §7.1.3 bitmask for P-521
            // `rejectNonCanonical`'s verdict is declassified inside p521
            // (the rejection is the spec's, and its probability is ~2^-260).
            p521.scalar.rejectNonCanonical(candidate, .big) catch continue; // sk >= n
            if (std.mem.allEqual(u8, &candidate, 0)) continue; // sk == 0
            var pk_point: p521.P521 = undefined;
            // A non-zero scalar below n times G is never the identity.
            p521.P521.mulInto(&pk_point, p521.P521.basePoint, &candidate, .big) catch unreachable;
            out.* = .{ .secret_key = candidate, .public_key = pk_point.toUncompressedSec1() };
            return;
        }
        @panic("hpke: P-521 DeriveKeyPair exhausted 256 candidates (probability ~2^-66000; RFC 9180 7.1.3 DeriveKeyPairError)");
    }

    /// One DH: x(sk · pk) through `p521.ecdhInto`. A peer that does not
    /// decode is `DeserializeError`; an identity result (impossible for a
    /// valid point and sk in [1, n − 1]) is `DhFailed`.
    fn dh(out: *[Nsk]u8, sk: *const [Nsk]u8, pk: *const PublicKey) error{ DeserializeError, DhFailed }!void {
        p521.ecdhInto(out, sk, pk) catch |err| return switch (err) {
            error.IdentityElement => error.DhFailed,
            error.InvalidEncoding, error.NonCanonical, error.NotSquare => error.DeserializeError,
        };
    }

    pub fn encapDeterministic(out: *Encapped, pkR: PublicKey, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, encapBody, .{ out, &pkR, eph });
    }

    fn encapBody(out: *Encapped, pkR: *const PublicKey, eph: *const KeyPair) EncapError!void {
        var z: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &z);
        try dh(&z, &eph.secret_key, pkR);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk..].* = pkR.*;
        extractAndExpand(HkdfSha512, kem_id, Nsecret, &out.shared_secret, &z, &kem_context);
        out.enc = eph.public_key;
    }

    pub fn encap(out: *Encapped, pkR: PublicKey, io: std.Io) EncapError!void {
        var eph: KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&eph));
        generateKeyPair(&eph, io);
        return encapDeterministic(out, pkR, &eph);
    }

    pub fn decap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, decapBody, .{ out, &enc, skR });
    }

    fn decapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair) DecapError!void {
        var z: [Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &z);
        try dh(&z, &skR.secret_key, enc);
        var kem_context: [2 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk..].* = skR.public_key;
        extractAndExpand(HkdfSha512, kem_id, Nsecret, out, &z, &kem_context);
    }

    pub fn authEncapDeterministic(out: *Encapped, pkR: PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        return burn.run(burn.kem_burn, EncapError!void, authEncapBody, .{ out, &pkR, skS, eph });
    }

    fn authEncapBody(out: *Encapped, pkR: *const PublicKey, skS: *const KeyPair, eph: *const KeyPair) EncapError!void {
        var z: [2 * Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &z);
        try dh(z[0..Nsk], &eph.secret_key, pkR);
        try dh(z[Nsk..], &skS.secret_key, pkR);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = eph.public_key;
        kem_context[Npk .. 2 * Npk].* = pkR.*;
        kem_context[2 * Npk ..].* = skS.public_key;
        extractAndExpand(HkdfSha512, kem_id, Nsecret, &out.shared_secret, &z, &kem_context);
        out.enc = eph.public_key;
    }

    pub fn authDecap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair, pkS: PublicKey) DecapError!void {
        return burn.run(burn.kem_burn, DecapError!void, authDecapBody, .{ out, &enc, skR, &pkS });
    }

    fn authDecapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair, pkS: *const PublicKey) DecapError!void {
        var z: [2 * Nsk]u8 = undefined;
        defer std.crypto.secureZero(u8, &z);
        try dh(z[0..Nsk], &skR.secret_key, enc);
        try dh(z[Nsk..], &skR.secret_key, pkS);
        var kem_context: [3 * Npk]u8 = undefined;
        kem_context[0..Npk].* = enc.*;
        kem_context[Npk .. 2 * Npk].* = skR.public_key;
        kem_context[2 * Npk ..].* = pkS.*;
        extractAndExpand(HkdfSha512, kem_id, Nsecret, out, &z, &kem_context);
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
    var got: X25519Kem.Encapped = undefined;
    try X25519Kem.encapDeterministic(&got, a1.pkRm, &eph);
    try testing.expectEqualSlices(u8, &a1.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &got.shared_secret);
    const skR = X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    var dec: [X25519Kem.Nsecret]u8 = undefined;
    try X25519Kem.decap(&dec, got.enc, &skR);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &dec);
}

test "DHKEM X25519 deriveKeyPair: RFC 9180 A.1.1 skEm/pkEm from ikmE (and skRm/pkRm from ikmR), byte-exact" {
    const a1 = @import("kat_rfc9180.zig").a1;
    var kpE: X25519Kem.KeyPair = undefined;
    X25519Kem.deriveKeyPair(&kpE, &a1.ikmE);
    try testing.expectEqualSlices(u8, &a1.skEm, &kpE.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkEm, &kpE.public_key);
    var kpR: X25519Kem.KeyPair = undefined;
    X25519Kem.deriveKeyPair(&kpR, &a1.ikmR);
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
    try testing.expectError(error.DhFailed, blk: {
        var o: X25519Kem.Encapped = undefined;
        break :blk X25519Kem.encapDeterministic(&o, low_order_pk, &eph);
    });
    const skR = X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    try testing.expectError(error.DhFailed, blk: {
        var o: [X25519Kem.Nsecret]u8 = undefined;
        break :blk X25519Kem.decap(&o, low_order_pk, &skR);
    });
}

test "DHKEM X25519 AuthEncap/AuthDecap: self-consistency round trip + wrong-pkS divergence" {
    // The BYTE-EXACT anchor for this fold is `kat_rfc9180.zig`'s A.1.3/
    // A.1.4 vectors (and A.3.3/A.3.4 for P-256) — this test covers the
    // property those vectors cannot: that a WRONG sender public key
    // produces a different shared secret, i.e. the auth binding is load-
    // bearing rather than decorative. Round-trip agreement alone would
    // prove nothing about spec conformance (both sides could share one
    // misreading), which is exactly why the vectors came first.
    var skR: X25519Kem.KeyPair = undefined;
    X25519Kem.deriveKeyPair(&skR, "hpke auth-mode test receiver ikm");
    var skS: X25519Kem.KeyPair = undefined;
    X25519Kem.deriveKeyPair(&skS, "hpke auth-mode test sender ikm");
    var eph: X25519Kem.KeyPair = undefined;
    X25519Kem.deriveKeyPair(&eph, "hpke auth-mode test ephemeral ikm");
    var got: X25519Kem.Encapped = undefined;
    try X25519Kem.authEncapDeterministic(&got, skR.public_key, &skS, &eph);
    try testing.expectEqualSlices(u8, &eph.public_key, &got.enc);
    var dec: [X25519Kem.Nsecret]u8 = undefined;
    try X25519Kem.authDecap(&dec, got.enc, &skR, skS.public_key);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
    // A wrong sender key must NOT decap to the same secret (the auth
    // binding is real, not decorative).
    var wrong: X25519Kem.KeyPair = undefined;
    X25519Kem.deriveKeyPair(&wrong, "hpke auth-mode test WRONG sender");
    var dec_wrong: [X25519Kem.Nsecret]u8 = undefined;
    try X25519Kem.authDecap(&dec_wrong, got.enc, &skR, wrong.public_key);
    try testing.expect(!std.mem.eql(u8, &got.shared_secret, &dec_wrong));
}

test "DHKEM P-256 Encap/Decap: RFC 9180 A.3 enc/shared_secret, byte-exact" {
    const a3 = @import("kat_rfc9180.zig").a3;
    const eph = P256Kem.KeyPair{ .secret_key = a3.skEm, .public_key = a3.pkEm };
    var got: P256Kem.Encapped = undefined;
    try P256Kem.encapDeterministic(&got, a3.pkRm, &eph);
    try testing.expectEqualSlices(u8, &a3.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a3.shared_secret, &got.shared_secret);
    const skR = P256Kem.KeyPair{ .secret_key = a3.skRm, .public_key = a3.pkRm };
    var dec: [P256Kem.Nsecret]u8 = undefined;
    try P256Kem.decap(&dec, got.enc, &skR);
    try testing.expectEqualSlices(u8, &a3.shared_secret, &dec);
}

test "DHKEM P-256 Encap/Decap: malformed SEC1 pkR fails closed with error.DeserializeError" {
    const a3 = @import("kat_rfc9180.zig").a3;
    const eph = P256Kem.KeyPair{ .secret_key = a3.skEm, .public_key = a3.pkEm };
    var bad = a3.pkRm;
    bad[0] = 0x05; // not a valid SEC1 tag
    try testing.expectError(error.DeserializeError, blk: {
        var o: P256Kem.Encapped = undefined;
        break :blk P256Kem.encapDeterministic(&o, bad, &eph);
    });
    const skR = P256Kem.KeyPair{ .secret_key = a3.skRm, .public_key = a3.pkRm };
    try testing.expectError(error.DeserializeError, blk: {
        var o: [P256Kem.Nsecret]u8 = undefined;
        break :blk P256Kem.decap(&o, bad, &skR);
    });
}

test "DHKEM P-256 deriveKeyPair: deterministic, on-curve, distinct per ikm (byte-exact anchor lives in the A.3.2/A.3.3/A.3.4 KATs)" {
    var kp1: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&kp1, "hpke p256 derive test ikm 1");
    var kp1_again: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&kp1_again, "hpke p256 derive test ikm 1");
    try testing.expectEqualSlices(u8, &kp1.secret_key, &kp1_again.secret_key);
    try testing.expectEqualSlices(u8, &kp1.public_key, &kp1_again.public_key);
    var kp2: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&kp2, "hpke p256 derive test ikm 2");
    try testing.expect(!std.mem.eql(u8, &kp1.secret_key, &kp2.secret_key));
    // public_key is a valid SEC1 point AND actually sk*G (Encap/Decap
    // round trip through it works).
    try testing.expectEqual(@as(u8, 0x04), kp1.public_key[0]);
    var eph: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&eph, "hpke p256 derive test ephemeral");
    var got: P256Kem.Encapped = undefined;
    try P256Kem.encapDeterministic(&got, kp1.public_key, &eph);
    var dec: [P256Kem.Nsecret]u8 = undefined;
    try P256Kem.decap(&dec, got.enc, &kp1);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
}

test "DHKEM P-256 AuthEncap/AuthDecap: self-consistency round trip" {
    var skR: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&skR, "hpke p256 auth test receiver");
    var skS: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&skS, "hpke p256 auth test sender");
    var eph: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&eph, "hpke p256 auth test ephemeral");
    var got: P256Kem.Encapped = undefined;
    try P256Kem.authEncapDeterministic(&got, skR.public_key, &skS, &eph);
    var dec: [P256Kem.Nsecret]u8 = undefined;
    try P256Kem.authDecap(&dec, got.enc, &skR, skS.public_key);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
    var wrong: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&wrong, "hpke p256 auth test WRONG sender");
    var dec_wrong: [P256Kem.Nsecret]u8 = undefined;
    try P256Kem.authDecap(&dec_wrong, got.enc, &skR, wrong.public_key);
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
    var skR: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&skR, "hpke p384 test receiver");
    var eph: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&eph, "hpke p384 test ephemeral");
    var got: P384Kem.Encapped = undefined;
    try P384Kem.encapDeterministic(&got, skR.public_key, &eph);
    try testing.expectEqualSlices(u8, &eph.public_key, &got.enc);
    var dec: [P384Kem.Nsecret]u8 = undefined;
    try P384Kem.decap(&dec, got.enc, &skR);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
}

test "DHKEM P-384 Encap/Decap: malformed SEC1 pkR fails closed with error.DeserializeError" {
    var skR: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&skR, "hpke p384 test receiver 3");
    var eph: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&eph, "hpke p384 test ephemeral 3");
    var bad: P384Kem.PublicKey = undefined;
    bad[0] = 0x05; // not a valid SEC1 tag
    try testing.expectError(error.DeserializeError, blk: {
        var o: P384Kem.Encapped = undefined;
        break :blk P384Kem.encapDeterministic(&o, bad, &eph);
    });
    try testing.expectError(error.DeserializeError, blk: {
        var o: [P384Kem.Nsecret]u8 = undefined;
        break :blk P384Kem.decap(&o, bad, &skR);
    });
}

test "DHKEM P-384 deriveKeyPair: deterministic, on-curve, distinct per ikm" {
    var kp1: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&kp1, "hpke p384 derive test ikm 1");
    var kp1_again: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&kp1_again, "hpke p384 derive test ikm 1");
    try testing.expectEqualSlices(u8, &kp1.secret_key, &kp1_again.secret_key);
    try testing.expectEqualSlices(u8, &kp1.public_key, &kp1_again.public_key);
    var kp2: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&kp2, "hpke p384 derive test ikm 2");
    try testing.expect(!std.mem.eql(u8, &kp1.secret_key, &kp2.secret_key));
    try testing.expectEqual(@as(u8, 0x04), kp1.public_key[0]);
    // public_key is actually sk*G: Encap/Decap round trip through it works.
    var eph: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&eph, "hpke p384 derive test ephemeral");
    var got: P384Kem.Encapped = undefined;
    try P384Kem.encapDeterministic(&got, kp1.public_key, &eph);
    var dec: [P384Kem.Nsecret]u8 = undefined;
    try P384Kem.decap(&dec, got.enc, &kp1);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
}

test "DHKEM P-384 AuthEncap/AuthDecap: self-consistency round trip + wrong-pkS divergence" {
    var skR: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&skR, "hpke p384 auth test receiver");
    var skS: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&skS, "hpke p384 auth test sender");
    var eph: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&eph, "hpke p384 auth test ephemeral");
    var got: P384Kem.Encapped = undefined;
    try P384Kem.authEncapDeterministic(&got, skR.public_key, &skS, &eph);
    var dec: [P384Kem.Nsecret]u8 = undefined;
    try P384Kem.authDecap(&dec, got.enc, &skR, skS.public_key);
    try testing.expectEqualSlices(u8, &got.shared_secret, &dec);
    var wrong: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&wrong, "hpke p384 auth test WRONG sender");
    var dec_wrong: [P384Kem.Nsecret]u8 = undefined;
    try P384Kem.authDecap(&dec_wrong, got.enc, &skR, wrong.public_key);
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

// ⚠ These four harnesses draw with `smith.bytes`, so a corpus entry is read
// RAW — no `u32` length header, unlike a `smith.slice` harness. One
// `fuzzedSec1Bytes` draw on the wire is therefore: `Npk` octets for the
// point, then the eight-octet little-endian word the tag selector
// (`valueRangeAtMost(u8, 0, 4)`) reads, and — for selector 4 only — eight
// more for the `smith.value(u8)` fallback behind it. `Sec1Corpus` writes
// exactly that.
//
// ⛔ Why the corpus exists at all: a ranged `Smith` draw returns the range
// MINIMUM when fewer than eight octets remain, and these four targets had NO
// corpus, so each ran exactly ONE input — an all-zero buffer with selector 0,
// i.e. `enc[0] = 0x00`. `fromSec1` refuses that on its first octet, so
// `decap`/`authDecap` returned `DeserializeError` every round and `mul`,
// `affineCoordinates` and `extractAndExpand` — the code these targets exist
// to run on peer-supplied bytes — had never executed under them. The
// tag-biasing recipe the comment above describes had likewise only ever
// selected 0: one distinct tag octet across the whole corpus, never 0x04.
//
// ⚠ Selectors 1 and 2 (tags 0x02/0x03) cannot ever produce an accepted
// point here and that is not a corpus defect: `enc`/`pkS` are `[Npk]u8`
// arrays, so `fromSec1` always sees 65 (or 97) octets and refuses a
// compressed tag on length. They are kept because the tag/length
// disagreement is itself a path worth walking.
fn Sec1Corpus(comptime N: usize, comptime cap: usize) type {
    return struct {
        const Self = @This();

        /// Two draws of `N` octets plus two eight-octet knob words each — the
        /// widest entry `authDecap`'s two `fuzzedSec1Bytes` calls can need.
        store: [cap][2 * (N + 16)]u8 = undefined,
        entries: [cap][]const u8 = undefined,
        used: usize = 0,
        n: usize = 0,

        /// Append the octets of ONE `fuzzedSec1Bytes` call to the entry
        /// currently being built.
        fn draw(self: *Self, point: *const [N]u8, choice: u64, raw_tag: u64) void {
            const s = &self.store[self.n];
            @memcpy(s[self.used..][0..N], point);
            self.used += N;
            std.mem.writeInt(u64, s[self.used..][0..8], choice, .little);
            self.used += 8;
            if (choice == 4) {
                std.mem.writeInt(u64, s[self.used..][0..8], raw_tag, .little);
                self.used += 8;
            }
        }

        /// Close the entry being built. Called with nothing drawn it yields
        /// the EMPTY seed — the single input these targets used to run.
        fn commit(self: *Self) void {
            self.entries[self.n] = self.store[self.n][0..self.used];
            self.used = 0;
            self.n += 1;
        }

        fn single(self: *Self, point: *const [N]u8, choice: u64, raw_tag: u64) void {
            self.draw(point, choice, raw_tag);
            self.commit();
        }
    };
}

const P256Corpus = Sec1Corpus(P256Kem.Npk, 16);
const P384Corpus = Sec1Corpus(P384Kem.Npk, 16);

/// Built from the module's own curve code rather than transcribed hex, so the
/// accepted seeds really are points `toUncompressedSec1` produces.
fn p256DecapSeeds(c: *P256Corpus) []const []const u8 {
    const g = P256.basePoint.toUncompressedSec1();
    const g2 = P256.basePoint.dbl().toUncompressedSec1();
    var off_curve = g;
    off_curve[64] ^= 0x01; // Y perturbed: a well-formed encoding of no point
    c.single(&g, 3, 0); // selector 3 -> tag 0x04 over a real point
    c.single(&g2, 3, 0); // 2*G, a DIFFERENT accepted point
    c.single(&g, 0, 0); // tag 0x00
    c.single(&g, 1, 0); // tag 0x02 over a 65-octet body: tag/length disagreement
    c.single(&g, 2, 0); // tag 0x03, likewise
    c.single(&g, 4, 0x04); // the arbitrary-tag branch, landing back on 0x04
    c.single(&g, 4, 0x99); // ...and on a tag no SEC1 encoding uses
    c.single(&off_curve, 3, 0); // 0x04 over coordinates that are not on the curve
    c.commit(); // the empty input this target used to run for ever
    return c.entries[0..c.n];
}

fn p256AuthDecapSeeds(c: *P256Corpus) []const []const u8 {
    const g = P256.basePoint.toUncompressedSec1();
    const g2 = P256.basePoint.dbl().toUncompressedSec1();
    c.draw(&g, 3, 0);
    c.draw(&g2, 3, 0);
    c.commit(); // both halves decode: the only path that reaches the second `mul`
    c.draw(&g, 3, 0);
    c.draw(&g2, 0, 0);
    c.commit(); // `enc` decodes, `pkS` does not: the SECOND `fromSec1`'s refusal
    c.draw(&g, 0, 0);
    c.draw(&g2, 3, 0);
    c.commit(); // `enc` refused first, so `pkS` is never decoded at all
    c.draw(&g2, 3, 0);
    c.draw(&g, 3, 0);
    c.commit(); // the same two points swapped: a DIFFERENT shared secret
    c.draw(&g, 4, 0x04);
    c.draw(&g2, 4, 0x04);
    c.commit(); // the arbitrary-tag branch on both halves
    c.draw(&g, 1, 0);
    c.draw(&g2, 2, 0);
    c.commit(); // tags 0x02/0x03: the tag/length disagreement in both halves
    c.draw(&g, 4, 0x99);
    c.draw(&g2, 4, 0x99);
    c.commit(); // ...and a tag no SEC1 encoding uses
    c.commit(); // the empty input this target used to run for ever
    return c.entries[0..c.n];
}

fn p384DecapSeeds(c: *P384Corpus) []const []const u8 {
    const g = P384.basePoint.toUncompressedSec1();
    const g2 = P384.basePoint.dbl().toUncompressedSec1();
    var off_curve = g;
    off_curve[96] ^= 0x01;
    c.single(&g, 3, 0);
    c.single(&g2, 3, 0);
    c.single(&g, 0, 0);
    c.single(&g, 1, 0);
    c.single(&g, 2, 0);
    c.single(&g, 4, 0x04);
    c.single(&g, 4, 0x99);
    c.single(&off_curve, 3, 0);
    c.commit();
    return c.entries[0..c.n];
}

fn p384AuthDecapSeeds(c: *P384Corpus) []const []const u8 {
    const g = P384.basePoint.toUncompressedSec1();
    const g2 = P384.basePoint.dbl().toUncompressedSec1();
    c.draw(&g, 3, 0);
    c.draw(&g2, 3, 0);
    c.commit();
    c.draw(&g, 3, 0);
    c.draw(&g2, 0, 0);
    c.commit();
    c.draw(&g, 0, 0);
    c.draw(&g2, 3, 0);
    c.commit();
    c.draw(&g2, 3, 0);
    c.draw(&g, 3, 0);
    c.commit();
    c.draw(&g, 4, 0x04);
    c.draw(&g2, 4, 0x04);
    c.commit();
    c.draw(&g, 1, 0);
    c.draw(&g2, 2, 0);
    c.commit();
    c.draw(&g, 4, 0x99);
    c.draw(&g2, 4, 0x99);
    c.commit();
    c.commit();
    return c.entries[0..c.n];
}

test "fuzz: P256Kem.decap never panics on arbitrary enc bytes" {
    var corpus: P256Corpus = .{};
    try testing.fuzz({}, fuzzP256DecapSmith, .{ .corpus = p256DecapSeeds(&corpus) });
}

// Generic over the SEC1-encoded width (comptime N) so P384Kem's fuzz
// harness below can reuse it verbatim at Npk=97 rather than duplicating
// the byte-biasing recipe.
//
// Under the driver's `Rng` (random bytes are never a point on the curve) half of
// the draws are instead a GENUINE public key of `Kem` with 0-3 octets damaged,
// so `fromSec1`'s accept branch and the multiplications behind it run.
fn fuzzedSec1Bytes(comptime Kem: type, comptime S: type, src: *S, buf: *[Kem.Npk]u8) void {
    if (S == fz.fuzz_driver.Rng and src.valueRangeAtMost(u8, 0, 3) != 0) {
        var ikm: [32]u8 = undefined;
        src.bytes(&ikm);
        var kp: Kem.KeyPair = undefined;
        Kem.deriveKeyPair(&kp, &ikm);
        buf.* = kp.public_key;
        // Two in three stay undamaged: auth mode needs BOTH points accepted.
        if (src.valueRangeAtMost(u8, 0, 2) == 0) {
            for (0..src.valueRangeAtMost(u8, 1, 3)) |_| buf[src.index(buf.len)] = src.value(u8);
        }
        return;
    }
    src.bytes(buf);
    buf[0] = switch (src.valueRangeAtMost(u8, 0, 4)) {
        0 => 0,
        1 => 2,
        2 => 3,
        3 => 4,
        else => src.value(u8),
    };
}

const fz = @import("fuzz_test.zig");
const KemMark = fz.Marker(enum { accepted, refused, genuine_agrees, tamper_diverges });

/// The receiver's half of the oracle: an `enc` the module's own `encap`
/// produced decaps to the sender's shared secret, and one damaged octet of it
/// yields a refusal or a DIFFERENT secret -- never the same one.
fn genuineDecap(comptime Kem: type, comptime S: type, src: *S, skR: *const Kem.KeyPair, auth: bool) !void {
    var ikm: [32]u8 = undefined;
    src.bytes(&ikm);
    var eph: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&eph, &ikm);
    ikm[0] ^= 0x80;
    var skS: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skS, &ikm);
    var sent: Kem.Encapped = undefined;
    if (auth) try Kem.authEncapDeterministic(&sent, skR.public_key, &skS, &eph) else try Kem.encapDeterministic(&sent, skR.public_key, &eph);
    var got: [Kem.Nsecret]u8 = undefined;
    const pk_s = skS.public_key;
    if (auth) try Kem.authDecap(&got, sent.enc, skR, pk_s) else try Kem.decap(&got, sent.enc, skR);
    if (!std.mem.eql(u8, &got, &sent.shared_secret)) return error.GenuineEncDecapsDiffers;
    KemMark.mark(.genuine_agrees);

    var bad = sent.enc;
    bad[src.index(bad.len)] ^= @as(u8, 1) << @as(u3, @intCast(src.index(8)));
    var bad_ss: [Kem.Nsecret]u8 = undefined;
    const r = if (auth) Kem.authDecap(&bad_ss, bad, skR, pk_s) else Kem.decap(&bad_ss, bad, skR);
    if (r) |_| {
        if (std.mem.eql(u8, &bad_ss, &sent.shared_secret)) return error.DamagedEncGivesSameSecret;
    } else |_| {}
    if (auth) { // the wrong sender key
        var other_ss: [Kem.Nsecret]u8 = undefined;
        if (Kem.authDecap(&other_ss, sent.enc, skR, eph.public_key)) |_| {
            if (std.mem.eql(u8, &other_ss, &sent.shared_secret)) return error.WrongSenderGivesSameSecret;
        } else |_| {}
    }
    KemMark.mark(.tamper_diverges);
}

fn decapHarness(comptime Kem: type, comptime key_label: []const u8, comptime auth: bool, comptime S: type, src: *S) !void {
    var skR: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skR, key_label);
    var enc: Kem.EncappedKey = undefined;
    fuzzedSec1Bytes(Kem, S, src, &enc);
    var pkS: Kem.PublicKey = undefined;
    if (auth) fuzzedSec1Bytes(Kem, S, src, &pkS);
    var ss: [Kem.Nsecret]u8 = undefined;
    const r = if (auth) Kem.authDecap(&ss, enc, &skR, pkS) else Kem.decap(&ss, enc, &skR);
    if (r) |_| KemMark.mark(.accepted) else |_| KemMark.mark(.refused);
    try genuineDecap(Kem, S, src, &skR, auth);
}

fn fuzzP256DecapSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzP256Decap(std.testing.Smith, smith, testing.allocator);
}

test "fuzz driver: HPKE_FUZZ (P-256 decap)" {
    try fz.fuzz_driver.run(fuzzP256Decap, .{ .prefix = "HPKE_FUZZ", .name = "hpke-p256-decap" });
}

test "fuzz harness: P-256 decap, 60 seeds, reaches every outcome" {
    try KemMark.reach(fuzzP256Decap, "hpke-p256-decap", 60);
}

fn fuzzP256Decap(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try decapHarness(P256Kem, "hpke fuzz decap receiver", false, S, src);
}

test "fuzz: P256Kem.authDecap never panics on arbitrary enc/pkS bytes" {
    var corpus: P256Corpus = .{};
    try testing.fuzz({}, fuzzP256AuthDecapSmith, .{ .corpus = p256AuthDecapSeeds(&corpus) });
}

fn fuzzP256AuthDecapSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzP256AuthDecap(std.testing.Smith, smith, testing.allocator);
}

test "fuzz driver: HPKE_FUZZ (P-256 authDecap)" {
    try fz.fuzz_driver.run(fuzzP256AuthDecap, .{ .prefix = "HPKE_FUZZ", .name = "hpke-p256-auth-decap" });
}

test "fuzz harness: P-256 authDecap, 60 seeds, reaches every outcome" {
    try KemMark.reach(fuzzP256AuthDecap, "hpke-p256-auth-decap", 60);
}

fn fuzzP256AuthDecap(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try decapHarness(P256Kem, "hpke fuzz auth-decap receiver", true, S, src);
}

// ── fuzz: P384Kem.decap/authDecap never panic on arbitrary enc/pkS bytes ──
// Same rationale as the P256Kem fuzz harness above — `enc`/`pkS` are
// attacker-controlled wire bytes decap must never panic on, and P384Kem's
// `fromSec1` is the analogous rejecting-decode step X25519Kem lacks.

test "fuzz: P384Kem.decap never panics on arbitrary enc bytes" {
    var corpus: P384Corpus = .{};
    try testing.fuzz({}, fuzzP384DecapSmith, .{ .corpus = p384DecapSeeds(&corpus) });
}

fn fuzzP384DecapSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzP384Decap(std.testing.Smith, smith, testing.allocator);
}

test "fuzz driver: HPKE_FUZZ (P-384 decap)" {
    try fz.fuzz_driver.run(fuzzP384Decap, .{ .prefix = "HPKE_FUZZ", .name = "hpke-p384-decap", .scale = 20 });
}

test "fuzz harness: P-384 decap, 40 seeds, reaches every outcome" {
    try KemMark.reach(fuzzP384Decap, "hpke-p384-decap", 40);
}

fn fuzzP384Decap(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try decapHarness(P384Kem, "hpke fuzz p384 decap receiver", false, S, src);
}

test "fuzz: P384Kem.authDecap never panics on arbitrary enc/pkS bytes" {
    var corpus: P384Corpus = .{};
    try testing.fuzz({}, fuzzP384AuthDecapSmith, .{ .corpus = p384AuthDecapSeeds(&corpus) });
}

fn fuzzP384AuthDecapSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzP384AuthDecap(std.testing.Smith, smith, testing.allocator);
}

test "fuzz driver: HPKE_FUZZ (P-384 authDecap)" {
    try fz.fuzz_driver.run(fuzzP384AuthDecap, .{ .prefix = "HPKE_FUZZ", .name = "hpke-p384-auth-decap", .scale = 20 });
}

test "fuzz harness: P-384 authDecap, 40 seeds, reaches every outcome" {
    try KemMark.reach(fuzzP384AuthDecap, "hpke-p384-auth-decap", 40);
}

fn fuzzP384AuthDecap(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try decapHarness(P384Kem, "hpke fuzz p384 auth-decap receiver", true, S, src);
}

/// Counts one corpus's worth of `fuzzedSec1Bytes` draws through the real
/// `Smith`, so the guard below measures the harness's own function rather
/// than a paraphrase of it.
fn Sec1Tally(comptime Kem: type, comptime cap: usize) type {
    return struct {
        const Self = @This();
        /// Distinct tag octets the selector produced. ⛔ NOT `accepted > 0`:
        /// this is the number the collapsed input could not have moved past
        /// 1, whatever the seeds were.
        tags: [256]bool = @splat(false),
        accepted: usize = 0,
        /// Distinct shared secrets. Acceptance alone would be satisfied by
        /// one point repeated; a second secret means a second point really
        /// went through `mul` and `extractAndExpand`.
        seen: [cap][Kem.Nsecret]u8 = undefined,
        distinct: usize = 0,

        fn distinctTags(self: *const Self) usize {
            var n: usize = 0;
            for (self.tags) |t| {
                if (t) n += 1;
            }
            return n;
        }

        fn record(self: *Self, ss: [Kem.Nsecret]u8) void {
            self.accepted += 1;
            for (self.seen[0..self.distinct]) |prev| {
                if (std.mem.eql(u8, &prev, &ss)) return;
            }
            self.seen[self.distinct] = ss;
            self.distinct += 1;
        }
    };
}

test "corpus: the P-256 enc/pkS seeds reach decap, and the counts are pinned" {
    var decap_corpus: P256Corpus = .{};
    var d: Sec1Tally(P256Kem, 16) = .{};
    var skR: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&skR, "hpke fuzz decap receiver");

    // The "before" state, executable rather than asserted in prose: with no
    // corpus these targets ran exactly one input, the empty one, and this is
    // what it produced — tag 0x00 and a refusal off `fromSec1`'s first octet.
    // 1 distinct tag, 0 accepted, 0 distinct shared secrets, for ever.
    {
        var smith: std.testing.Smith = .{ .in = "" };
        var enc: P256Kem.EncappedKey = undefined;
        fuzzedSec1Bytes(P256Kem, std.testing.Smith, &smith, &enc);
        try testing.expectEqual(@as(u8, 0), enc[0]);
        try testing.expectError(error.DeserializeError, blk: {
            var o: [P256Kem.Nsecret]u8 = undefined;
            break :blk P256Kem.decap(&o, enc, &skR);
        });
    }

    for (p256DecapSeeds(&decap_corpus)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var enc: P256Kem.EncappedKey = undefined;
        fuzzedSec1Bytes(P256Kem, std.testing.Smith, &smith, &enc);
        d.tags[enc[0]] = true;
        var ss: [P256Kem.Nsecret]u8 = undefined;
        P256Kem.decap(&ss, enc, &skR) catch continue;
        d.record(ss);
    }
    try testing.expectEqual(@as(usize, 5), d.distinctTags()); // 0x00 0x02 0x03 0x04 0x99
    try testing.expectEqual(@as(usize, 3), d.accepted);
    try testing.expectEqual(@as(usize, 2), d.distinct); // G and 2*G

    var auth_corpus: P256Corpus = .{};
    var a: Sec1Tally(P256Kem, 16) = .{};
    var authR: P256Kem.KeyPair = undefined;
    P256Kem.deriveKeyPair(&authR, "hpke fuzz auth-decap receiver");
    for (p256AuthDecapSeeds(&auth_corpus)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var enc: P256Kem.EncappedKey = undefined;
        fuzzedSec1Bytes(P256Kem, std.testing.Smith, &smith, &enc);
        var pkS: P256Kem.PublicKey = undefined;
        fuzzedSec1Bytes(P256Kem, std.testing.Smith, &smith, &pkS);
        a.tags[enc[0]] = true;
        a.tags[pkS[0]] = true;
        var ss: [P256Kem.Nsecret]u8 = undefined;
        P256Kem.authDecap(&ss, enc, &authR, pkS) catch continue;
        a.record(ss);
    }
    try testing.expectEqual(@as(usize, 5), a.distinctTags());
    try testing.expectEqual(@as(usize, 3), a.accepted);
    try testing.expectEqual(@as(usize, 2), a.distinct); // (G, 2G) and the swap
}

test "corpus: the P-384 enc/pkS seeds reach decap, and the counts are pinned" {
    var decap_corpus: P384Corpus = .{};
    var d: Sec1Tally(P384Kem, 16) = .{};
    var skR: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&skR, "hpke fuzz p384 decap receiver");
    for (p384DecapSeeds(&decap_corpus)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var enc: P384Kem.EncappedKey = undefined;
        fuzzedSec1Bytes(P384Kem, std.testing.Smith, &smith, &enc);
        d.tags[enc[0]] = true;
        var ss: [P384Kem.Nsecret]u8 = undefined;
        P384Kem.decap(&ss, enc, &skR) catch continue;
        d.record(ss);
    }
    try testing.expectEqual(@as(usize, 5), d.distinctTags()); // 0x00 0x02 0x03 0x04 0x99
    try testing.expectEqual(@as(usize, 3), d.accepted);
    try testing.expectEqual(@as(usize, 2), d.distinct); // G and 2*G

    var auth_corpus: P384Corpus = .{};
    var a: Sec1Tally(P384Kem, 16) = .{};
    var authR: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&authR, "hpke fuzz p384 auth-decap receiver");
    for (p384AuthDecapSeeds(&auth_corpus)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var enc: P384Kem.EncappedKey = undefined;
        fuzzedSec1Bytes(P384Kem, std.testing.Smith, &smith, &enc);
        var pkS: P384Kem.PublicKey = undefined;
        fuzzedSec1Bytes(P384Kem, std.testing.Smith, &smith, &pkS);
        a.tags[enc[0]] = true;
        a.tags[pkS[0]] = true;
        var ss: [P384Kem.Nsecret]u8 = undefined;
        P384Kem.authDecap(&ss, enc, &authR, pkS) catch continue;
        a.record(ss);
    }
    try testing.expectEqual(@as(usize, 5), a.distinctTags());
    try testing.expectEqual(@as(usize, 3), a.accepted);
    try testing.expectEqual(@as(usize, 2), a.distinct); // (G, 2G) and the swap
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
    var skR: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&skR, "hpke p384 kdf-discriminator receiver");
    var eph: P384Kem.KeyPair = undefined;
    P384Kem.deriveKeyPair(&eph, "hpke p384 kdf-discriminator ephemeral");
    var got: P384Kem.Encapped = undefined;
    try P384Kem.encapDeterministic(&got, skR.public_key, &eph);

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
