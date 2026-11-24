// SPDX-License-Identifier: MIT

//! tlock — the `Ciphertext` wire struct and the two Fable-hard
//! cryptographic cores, `encrypt`/`decrypt` (REAL — implemented and
//! byte-exact-verified against a genuine drand-Go-produced interop
//! ciphertext, see `kat_test.zig`'s interop vector). This
//! file is the BF-IBE (Boneh-Franklin identity-based encryption,
//! "FullIdent" — Boneh & Franklin, "Identity-Based Encryption from the
//! Weil Pairing", CRYPTO 2001, §4.2) assembly drand's `tlock` (Gailly/
//! Melissaris/Romailler) wraps around a beacon round number as the
//! "identity": encrypt to a FUTURE round (nobody can decrypt yet,
//! because nobody has the private key — the round's threshold-BLS
//! signature — until the beacon publishes it), decrypt once that
//! signature exists.
//!
//! ## The scheme, end to end (quicknet variant — see `ciphersuite.zig`'s
//! module doc comment for why THIS variant, not the others)
//!
//! - **Setup** (not this module's concern — the caller supplies these):
//!   a drand beacon's master public key `P_pub ∈ G2` (96-byte
//!   compressed), and, once a round is reached, that round's threshold-
//!   BLS signature `σ_round ∈ G1` (48-byte compressed) satisfying
//!   `e(σ_round, G2_generator) == e(h1(beaconId(round)), P_pub)` — the
//!   exact equation `bls12_381.pairing.pairingCheck` can verify (see
//!   `kat_test.zig`'s ungated pairing-sanity test against a REAL
//!   published quicknet round). `σ_round` IS this scheme's BF-IBE
//!   private key for the identity `beaconId(round)`.
//! - **`encrypt(p_pub, round, message, sigma)`** — this file's Fable
//!   core:
//!   1. `id = ciphersuite.beaconId(round)` (32-byte SHA-256 digest).
//!   2. `Qid = ciphersuite.h1(id) ∈ G1`.
//!   3. `Gid = pairing(Qid, p_pub) ∈ Gt` — `bls12_381.pairing.pairing`
//!      takes `(G1, G2)` in exactly this order, matching drand/kyber's
//!      `EncryptCCAonG2`'s `s.Pair(Qid, master)`.
//!   4. `sigma` is the caller-supplied `block_bytes`-wide randomness
//!      (BF-IBE's "FullIdent" padding — see this function's own doc
//!      comment below for why it is a PARAMETER, not drawn internally).
//!   5. `r = ciphersuite.h3(sigma, message) ∈ Fr`.
//!   6. `U = r * G2_generator ∈ G2` — `g2.Jacobian.fromAffine(g2.Affine.
//!      generator).scalarMul(r).toAffine()`.
//!   7. `gid_r = Gid^r ∈ Gt` — a `Gt`-GROUP EXPONENTIATION by the
//!      scalar `r` (NOT a pairing call — encrypt has no private
//!      "secret" to fold `r` into one of the pairing's own arguments
//!      the way `decrypt` does; it must exponentiate the already-
//!      computed `Gid` directly) — `Gid.pow(&r)`, `bls12_381`'s
//!      constant-time fixed-window `Fp12.pow` (shared with `ibe`).
//!   8. `V = sigma XOR ciphersuite.h2(block_bytes, gid_r)`.
//!   9. `W = message XOR ciphersuite.h4(block_bytes, &sigma)`.
//!   10. return `Ciphertext{ .u = U, .v = V, .w = W }`.
//! - **`decrypt(round_signature, ct)`** — this file's other Fable core:
//!   1. `gid_r = pairing.pairing(round_signature, ct.u) ∈ Gt` — ONE
//!      pairing call reconstructs exactly the `Gid^r` value `encrypt`
//!      had to exponentiate for, by bilinearity: `e(σ_round, U) =
//!      e(sk*Qid, r*G2gen) = e(Qid, G2gen)^(sk*r) = e(Qid,
//!      sk*G2gen)^r = e(Qid, P_pub)^r = Gid^r`. This is the entire
//!      reason BF-IBE is practical: the DECRYPTOR gets the
//!      exponentiated value for free from one pairing, while the
//!      ENCRYPTOR (who does not have `sk`) must actually exponentiate
//!      (step 7 above).
//!   2. `sigma = ct.v XOR ciphersuite.h2(block_bytes, gid_r)`.
//!   3. `message = ct.w XOR ciphersuite.h4(block_bytes, &sigma)`.
//!   4. **FO consistency check (the CCA-security step — MUST NOT be
//!      skipped):** recompute `r' = ciphersuite.h3(sigma, message)`,
//!      then `U' = r' * G2_generator`; if `U' != ct.u`, REJECT (return
//!      an error, never a partially-decrypted `message`) — this is what
//!      stops a chosen-ciphertext attacker from tampering with `V`/`W`
//!      and having `decrypt` silently return garbage that LOOKS like a
//!      message: only a ciphertext genuinely produced by `encrypt` with
//!      matching internal randomness passes this check. Fujisaki-
//!      Okamoto transform, Boneh-Franklin §4.2's `FullIdent`.
//!   5. return `message`.
//!
//! ## Ciphertext group placement (quicknet / `SigsOnG1ID`)
//!
//! `U ∈ G2` (96-byte compressed) — NOT `G1`, despite the scheme's own
//! `"bls-unchained-g1-rfc9380"` name (see `ciphersuite.zig`'s "Variant
//! confirmation" section for why). `round_signature`/the BF-IBE private
//! key IS in `G1` (48-byte compressed) — that asymmetry (master
//! pubkey + `U` in the BIGGER group, identity + private-key signature
//! in the SMALLER group) is exactly quicknet's whole design point:
//! signatures are gossiped/stored far more often than the master public
//! key, so quicknet keeps them small.
//!
//! ## Wire format
//!
//! `Ciphertext.toBytes`/`fromBytes`: `U` (96-byte `G2` compressed) `||`
//! `V` (16 bytes) `||` `W` (16 bytes) = 128 bytes total — byte-for-byte
//! drand's own `tlock.go` `CiphertextToBytes`/`BytesToCiphertext` for
//! the `SigsOnG1ID` scheme (`scheme.KeyGroup.PointLen()` = 96 for that
//! scheme's `KeyGroup = G2`, `cipherVLen = cipherWLen = 16`).
//!
//! ## The envelope lives next door
//!
//! The outer `age`-format envelope `drand/tlock`'s `tle` wraps THIS
//! 128-byte `Ciphertext` in (the `tlock` stanza, header MAC, STREAM
//! payload, ASCII armor) is `age.zig`; this file stays the BF-IBE
//! primitive `tlock.go`'s `TimeLock`/`TimeUnlock` call directly.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const ciphersuite = @import("ciphersuite.zig");
const gate = @import("gate.zig");
const burn = @import("burn.zig");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;
const Fp2 = bls12_381.Fp2;
const Fp6 = bls12_381.Fp6;
const Fp12 = bls12_381.Fp12;
const Fr = bls12_381.Fr;

pub const block_bytes = ciphersuite.block_bytes;

// ── Ciphertext: REAL struct + byte codec ────────────────────────────

/// The `(U, V, W)` BF-IBE ciphertext (Boneh-Franklin §4.2's
/// `FullIdent` output shape), quicknet-specialized: `U ∈ G2`. See this
/// file's module doc comment for the full construction and
/// `ciphersuite.zig` for why `U` lives in `G2` despite the
/// `SigsOnG1ID` scheme's name.
pub const Ciphertext = struct {
    /// `r * G2_generator` — the randomized "commitment" half of the
    /// ciphertext; `decrypt`'s FO check recomputes this from the
    /// recovered `(sigma, message)` and rejects on mismatch.
    u: g2.Affine,
    /// `sigma XOR H2(Gid^r)` — the random pad `sigma`, masked by a
    /// hash of the pairing value only someone with `round_signature`
    /// (or the encryptor, who computed `Gid^r` directly) can recover.
    v: [block_bytes]u8,
    /// `message XOR H4(sigma)` — the actual plaintext block, masked by
    /// a hash of `sigma` (recoverable only after `v` is unmasked).
    w: [block_bytes]u8,

    pub const encoded_bytes = g2.compressed_bytes + block_bytes + block_bytes; // 96 + 16 + 16 = 128

    /// `U (96B compressed G2) || V (16B) || W (16B)` — byte-for-byte
    /// drand's own `tlock.go` `CiphertextToBytes` for the `SigsOnG1ID`
    /// scheme. REAL: plain concatenation over `bls12_381`'s already-
    /// real `g2.toBytesCompressed`.
    pub fn toBytes(self: Ciphertext) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..g2.compressed_bytes].* = g2.toBytesCompressed(self.u);
        out[g2.compressed_bytes..][0..block_bytes].* = self.v;
        out[g2.compressed_bytes + block_bytes ..][0..block_bytes].* = self.w;
        return out;
    }

    /// Inverse of `toBytes`. `g2.fromBytesCompressed` refuses a `U`
    /// outside `G2`, so the pairing in `decrypt` never runs on a
    /// torsion point; `decrypt`'s own consistency check (`U ==
    /// r*gen`) stays the scheme-specific guard. REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) g2.G2Error!Ciphertext {
        const u = try g2.fromBytesCompressed(bytes[0..g2.compressed_bytes].*);
        return .{
            .u = u,
            .v = bytes[g2.compressed_bytes..][0..block_bytes].*,
            .w = bytes[g2.compressed_bytes + block_bytes ..][0..block_bytes].*,
        };
    }
};

/// Converts a `Gt` element from this module's CANONICAL pairing value
/// to the representation drand actually hashes — the element's CUBE.
///
/// **The interop finding this encodes (root-caused, this
/// module's Fable pass — see `SPEC.md`'s "Gt serialization" section):**
/// drand/kyber's `GT.MarshalBinary` is `kilic/bls12-381`'s
/// `GT.ToBytes`, whose tower layout and byte nesting are IDENTICAL to
/// `bls12_381.Fp12.toBytes` (`c1||c0` high-to-low at every tower
/// level, big-endian 48-byte `Fp` limbs — no reordering needed), BUT
/// kilic's pairing VALUE is the canonical optimal-ate pairing's
/// third power: kilic's final exponentiation uses the Fuentes-
/// Castañeda-Knapp-Rodríguez-Henríquez (ePrint 2011/465) hard-part
/// chain, which computes `f^(3d)` — a fixed CUBE of the canonical
/// `f^d` this repo's `bls12_381.pairing` deliberately implements (see
/// `pairing.zig`'s `finalExpHardPart` doc comment, which pins the
/// exact-`d` Hayashida et al. chain against the IETF draft's
/// canonical KAT vector for exactly this reason). Both are perfectly
/// good bilinear pairings — `e^3` is bilinear and non-degenerate
/// since `gcd(3, r) = 1` — which is why every self-consistent test
/// (round-trip, tamper, bilinearity, pairingCheck) passes with either
/// convention and ONLY a cross-implementation byte-exact vector can
/// expose the difference. Verified empirically: `kilic`'s published
/// pairing output vectors (noble-curves' Go-generated
/// `go_pairing_vectors/pairing.json`, produced directly by
/// `kilic/bls12-381`) equal `canonical^(3n²)` for the `n`-th vector,
/// byte-for-byte in `Fp12.toBytes` layout, across multiple samples —
/// and the real drand-produced interop ciphertext in `kat_test.zig`
/// decrypts byte-exactly with this cube in place (and rejects
/// without it).
///
/// Bilinearity commutes with the cube, so applying it AFTER
/// `Fp12.pow`/`pairing` is exactly drand's `(Gid_kilic)^r`:
/// `(gid^r)^3 = (gid^3)^r`.
fn gtToDrandRepr(gt: Fp12) Fp12 {
    return gt.square().mul(gt);
}

// ── encrypt / decrypt: FABLE CORE ───────────────────────────────────

pub const DecryptError = error{
    /// The Fiat-Shamir-Okamoto consistency check (`U == r*gen` after
    /// recomputing `r` from the recovered `(sigma, message)`) failed —
    /// the ciphertext was tampered with, or `round_signature` does not
    /// correspond to the round `U`/`V`/`W` were encrypted under. This is
    /// the CCA-rejection outcome; `decrypt` must NEVER return a
    /// `message` when this check fails (see this file's module doc
    /// comment, step 4).
    FoCheckFailed,
};

/// **FABLE CORE — REAL.** BF-IBE FullIdent encryption (Boneh-Franklin
/// §4.2), quicknet variant. See this file's module doc comment for the
/// full 10-step construction this function implements
/// (`id -> Qid -> Gid -> r -> U -> gid_r -> V -> W`). Byte-exact
/// interop with drand's Go implementation is pinned by `kat_test.zig`'s
/// interop vector (re-encrypting with the vector's recovered
/// `(message, sigma)` reproduces the Go-produced ciphertext exactly).
///
/// ## Randomness — explicit parameter, not internal entropy
///
/// `sigma` (BF-IBE's random `block_bytes`-wide pad — drand/kyber's
/// `rand.Read(sigma)`) is a PLAIN PARAMETER here, not read from
/// `std.Io`/internal entropy directly — mirroring `bbs`/`frost`'s
/// "randomness is an explicit input" convention (`bbs/src/root.zig`'s
/// "Randomness" section, and this module's own `ciphersuite.
/// randomSigma`). This is what lets a KAT harness pin the ciphertext
/// byte-exactly: `encrypt`'s OTHER inputs (`p_pub`, `round`, `message`)
/// are already fully deterministic, so supplying `sigma` explicitly
/// makes the entire output reproducible — a production caller instead
/// sources `sigma` from `ciphersuite.randomSigma(io)`.
///
/// `message.len`/`sigma.len` are both fixed to `block_bytes` (16,
/// drand's own `tlock.go` DEK width — see `ciphersuite.block_bytes`'s
/// doc comment) rather than the fully-generic arbitrary-length
/// `msg`/`sigma` drand/kyber's own `EncryptCCAonG2` allows (bounded
/// only by `sha256.digest_length`) — this module targets drand's ACTUAL
/// wire format, not kyber's more general primitive.
///
/// `message` and `sigma` are secrets, so they come in by pointer; the body
/// runs one frame down and the stack it dirtied (`r`, the pairing value,
/// both masks) is zeroed after it (`burn.zig`).
pub fn encrypt(p_pub: g2.Affine, round: u64, message: *const [block_bytes]u8, sigma: *const [block_bytes]u8) Ciphertext {
    return burn.run(burn.crypt_burn, Ciphertext, encryptBody, .{ p_pub, round, message, sigma });
}

fn encryptBody(p_pub: g2.Affine, round: u64, message: *const [block_bytes]u8, sigma: *const [block_bytes]u8) Ciphertext {
    // Steps 1-3: identity -> Qid -> Gid. `pairing.pairing` takes
    // `(G1, G2)` in exactly drand/kyber's `s.Pair(Qid, master)` order.
    const qid = ciphersuite.h1(ciphersuite.beaconId(round));
    const gid = pairing.pairing(qid, p_pub);

    // Step 5: r = H3(sigma, M) — the FO-transform binding scalar.
    const r = ciphersuite.h3(sigma, message);

    // Step 6: U = r * G2_generator (constant-time scalarMul).
    const u = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r).toAffine();

    // Step 7: gid_r = Gid^r — Gt exponentiation (bls12_381's constant-time Fp12.pow).
    const gid_r = gid.pow(&r);

    // Step 8: V = sigma XOR H2(gid_r) — hashed in drand's Gt
    // representation (the canonical value's cube; see gtToDrandRepr).
    var v = ciphersuite.h2(block_bytes, gtToDrandRepr(gid_r));
    for (&v, sigma) |*b, s| b.* ^= s;

    // Step 9: W = M XOR H4(sigma).
    var w = ciphersuite.h4(block_bytes, sigma);
    for (&w, message) |*b, m| b.* ^= m;

    return .{ .u = u, .v = v, .w = w };
}

/// **FABLE CORE — REAL.** BF-IBE FullIdent decryption + the
/// Fiat-Shamir-Okamoto consistency check. See this file's module doc
/// comment for the full construction this function implements
/// (`gid_r -> sigma -> message -> recompute r -> check U`). Byte-exact
/// interop with drand's Go implementation is pinned by `kat_test.zig`'s
/// interop vector (decrypting a genuine Go-`tle`-produced ciphertext
/// with the genuine published round signature).
///
/// `round_signature` is the drand beacon's published threshold-BLS
/// signature for the round `ct` was encrypted to (`G1`, 48-byte
/// compressed once decoded) — this IS the BF-IBE private key for that
/// round's identity; this function does NOT verify it against a beacon
/// public key (that is `bls12_381.bls_sig`-style verification, a
/// SEPARATE, caller-side step — see `kat_test.zig`'s ungated pairing
/// sanity test for how to perform it independently). Returns
/// `error.FoCheckFailed` (never a garbage `message`) if the recomputed
/// `U' != ct.u` — the CCA-rejection path; see this file's module doc
/// comment, step 4, for why this check is security-critical and must
/// run on every call, unconditionally.
///
/// The plaintext is written to `out` (zeroed on error). The body runs one
/// frame down and the stack it dirtied is zeroed after it (`burn.zig`).
pub fn decrypt(out: *[block_bytes]u8, round_signature: g1.Affine, ct: Ciphertext) DecryptError!void {
    burn.run(burn.crypt_burn, DecryptError!void, decryptBody, .{ out, round_signature, ct }) catch |e| {
        std.crypto.secureZero(u8, out);
        return e;
    };
}

fn decryptBody(out: *[block_bytes]u8, round_signature: g1.Affine, ct: Ciphertext) DecryptError!void {
    // Step 1: gid_r = e(round_signature, U) — ONE pairing call
    // reconstructs encrypt's Gid^r by bilinearity (see the module doc
    // comment). This is also where a drand-produced ciphertext pins
    // the Gt byte order: if Fp12.toBytes' coefficient layout differed
    // from kilic's GT.ToBytes, the H2 mask below would be garbage and
    // the FO check would reject with overwhelming probability — so
    // kat_test.zig's byte-exact interop vector passing IS the
    // serialization proof.
    const gid_r = pairing.pairing(round_signature, ct.u);

    // Step 2: sigma = V XOR H2(gid_r) — hashed in drand's Gt
    // representation (the canonical value's cube; see gtToDrandRepr).
    // `sigma` is pure per-decrypt scratch (BF-IBE's random pad — never part
    // of the return value), so it is wiped unconditionally at scope exit.
    var sigma = ciphersuite.h2(block_bytes, gtToDrandRepr(gid_r));
    defer std.crypto.secureZero(u8, &sigma);
    for (&sigma, ct.v) |*b, x| b.* ^= x;

    // Step 3: message = W XOR H4(sigma).
    const message = out;
    message.* = ciphersuite.h4(block_bytes, &sigma);
    for (message, ct.w) |*b, x| b.* ^= x;

    // Step 4: FO/CCA consistency — recompute r' = H3(sigma, message)
    // and reject unless U == r' * G2_generator. Compare via the
    // canonical compressed encoding (unique for every point incl.
    // infinity), as interop with drand requires. The check's
    // outcome (accept/reject) is public, so a non-constant-time byte
    // compare is fine here; what must NOT happen is returning a
    // partially-decrypted message on mismatch. `r_check` is pure scratch
    // (the FO-transform binding scalar, recomputed only to validate `ct.u`)
    // and is wiped unconditionally; `message` is wiped ONLY on the reject
    // path below — the success path returns it as the decrypted plaintext.
    var r_check = ciphersuite.h3(&sigma, message);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r_check));
    const u_check = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r_check).toAffine();
    if (!std.mem.eql(u8, &g2.toBytesCompressed(u_check), &g2.toBytesCompressed(ct.u))) {
        // CCA-reject: never leave a partially/wrongly-decrypted plaintext
        // resident in memory once it is being discarded as invalid.
        std.crypto.secureZero(u8, message);
        return error.FoCheckFailed;
    }
}

// ── the G2-signature scheme ("pedersen-bls-unchained") ──────────────

/// The `(U, V, W)` ciphertext of the **G2-signature** scheme (drand's
/// `UnchainedSchemeID` / `"pedersen-bls-unchained"`, kyber's `EncryptCCAonG1`):
/// the roles of the two groups are swapped against `Ciphertext`. The beacon's
/// master public key and `U` live in `G1` (48 bytes compressed), the identity
/// is hashed onto `G2` and the round signature, the IBE private key, is a `G2`
/// point (96 bytes). `U (48) || V (16) || W (16)` = 80 bytes, byte for byte
/// `tlock.go`'s `CiphertextToBytes` for that scheme (`KeyGroup` = `G1`).
pub const CiphertextSigG2 = struct {
    /// `r * G1_generator`; `decryptSigG2`'s FO check recomputes it.
    u: g1.Affine,
    v: [block_bytes]u8,
    w: [block_bytes]u8,

    pub const encoded_bytes = g1.compressed_bytes + block_bytes + block_bytes; // 48 + 16 + 16 = 80

    pub fn toBytes(self: CiphertextSigG2) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..g1.compressed_bytes].* = g1.toBytesCompressed(self.u);
        out[g1.compressed_bytes..][0..block_bytes].* = self.v;
        out[g1.compressed_bytes + block_bytes ..][0..block_bytes].* = self.w;
        return out;
    }

    /// `g1.fromBytesCompressed` refuses a `U` outside `G1`.
    pub fn fromBytes(bytes: [encoded_bytes]u8) g1.G1Error!CiphertextSigG2 {
        const u = try g1.fromBytesCompressed(bytes[0..g1.compressed_bytes].*);
        return .{
            .u = u,
            .v = bytes[g1.compressed_bytes..][0..block_bytes].*,
            .w = bytes[g1.compressed_bytes + block_bytes ..][0..block_bytes].*,
        };
    }
};

/// BF-IBE FullIdent encryption for the G2-signature scheme: `encrypt` with the
/// groups swapped. `p_pub` is the beacon's `G1` public key. The construction
/// (cross-checked against `drand/tlock-js`'s `encryptOnG1`, MIT OR Apache-2.0,
/// and the genuine Go-produced ciphertext in `kat_test.zig`):
///
///   `Qid = h1SigG2(beaconId(round)) ∈ G2`,
///   `Gid = e(p_pub, Qid)` (`pairing(G1, G2)` again, the orientation of the
///   pairing call is the same as `encrypt`'s), `r = h3(sigma, message)`,
///   `U = r·G1_generator`, `V = sigma XOR h2(Gid^r)`, `W = message XOR h4(sigma)`.
///
/// `h2`/`h3`/`h4` and the Gt representation (`gtToDrandRepr`) are exactly
/// `encrypt`'s. Randomness, secrecy and the dead-stack burn: as `encrypt`.
pub fn encryptSigG2(p_pub: g1.Affine, round: u64, message: *const [block_bytes]u8, sigma: *const [block_bytes]u8) CiphertextSigG2 {
    return burn.run(burn.crypt_burn, CiphertextSigG2, encryptSigG2Body, .{ p_pub, round, message, sigma });
}

fn encryptSigG2Body(p_pub: g1.Affine, round: u64, message: *const [block_bytes]u8, sigma: *const [block_bytes]u8) CiphertextSigG2 {
    const qid = ciphersuite.h1SigG2(ciphersuite.beaconId(round));
    const gid = pairing.pairing(p_pub, qid);
    const r = ciphersuite.h3(sigma, message);
    const u = g1.Jacobian.fromAffine(g1.Affine.generator).scalarMul(r).toAffine();
    const gid_r = gid.pow(&r);
    var v = ciphersuite.h2(block_bytes, gtToDrandRepr(gid_r));
    for (&v, sigma) |*b, s| b.* ^= s;
    var w = ciphersuite.h4(block_bytes, sigma);
    for (&w, message) |*b, m| b.* ^= m;
    return .{ .u = u, .v = v, .w = w };
}

/// BF-IBE FullIdent decryption + the Fujisaki-Okamoto check for the
/// G2-signature scheme. `round_signature` is the beacon's `G2` signature for
/// the round (the IBE private key); the check is `U == r'·G1_generator`.
/// Errors, wiping and burn: as `decrypt`.
pub fn decryptSigG2(out: *[block_bytes]u8, round_signature: g2.Affine, ct: CiphertextSigG2) DecryptError!void {
    burn.run(burn.crypt_burn, DecryptError!void, decryptSigG2Body, .{ out, round_signature, ct }) catch |e| {
        std.crypto.secureZero(u8, out);
        return e;
    };
}

fn decryptSigG2Body(out: *[block_bytes]u8, round_signature: g2.Affine, ct: CiphertextSigG2) DecryptError!void {
    const gid_r = pairing.pairing(ct.u, round_signature);
    var sigma = ciphersuite.h2(block_bytes, gtToDrandRepr(gid_r));
    defer std.crypto.secureZero(u8, &sigma);
    for (&sigma, ct.v) |*b, x| b.* ^= x;
    const message = out;
    message.* = ciphersuite.h4(block_bytes, &sigma);
    for (message, ct.w) |*b, x| b.* ^= x;
    var r_check = ciphersuite.h3(&sigma, message);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r_check));
    const u_check = g1.Jacobian.fromAffine(g1.Affine.generator).scalarMul(r_check).toAffine();
    if (!std.mem.eql(u8, &g1.toBytesCompressed(u_check), &g1.toBytesCompressed(ct.u))) {
        std.crypto.secureZero(u8, message);
        return error.FoCheckFailed;
    }
}

// ── tests: Ciphertext codec (REAL, ungated) ─────────────────────────

test "Ciphertext.encoded_bytes is 128 (96 G2 + 16 V + 16 W), matching drand's tlock.go wire format" {
    try std.testing.expectEqual(@as(usize, 128), Ciphertext.encoded_bytes);
}

test "Ciphertext.toBytes/fromBytes round-trip (generator U, arbitrary V/W)" {
    const ct: Ciphertext = .{
        .u = g2.Affine.generator,
        .v = @as([block_bytes]u8, @splat(0xab)),
        .w = @as([block_bytes]u8, @splat(0xcd)),
    };
    const bytes = ct.toBytes();
    try std.testing.expectEqual(@as(usize, Ciphertext.encoded_bytes), bytes.len);

    const decoded = try Ciphertext.fromBytes(bytes);
    try std.testing.expect(decoded.u.x.eql(g2.Affine.generator.x));
    try std.testing.expectEqualSlices(u8, &ct.v, &decoded.v);
    try std.testing.expectEqualSlices(u8, &ct.w, &decoded.w);
}

test "Ciphertext.fromBytes rejects a malformed G2 encoding (V/W untouched, U corrupted)" {
    var bytes = (Ciphertext{
        .u = g2.Affine.generator,
        .v = @as([block_bytes]u8, @splat(0)),
        .w = @as([block_bytes]u8, @splat(0)),
    }).toBytes();
    // Flip the compression-flag byte into an invalid combination: set
    // both the compressed bit and the infinity bit with a nonzero
    // x-coordinate tail present (same corruption idiom g1.zig/g2.zig's
    // own decode-rejection tests use) — set the top byte to something
    // that is not a valid flag combination.
    bytes[0] = 0xFF;
    try std.testing.expectError(error.InvalidEncoding, Ciphertext.fromBytes(bytes));
}
