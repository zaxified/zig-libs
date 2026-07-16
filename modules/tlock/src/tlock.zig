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
//!      computed `Gid` directly). `bls12_381.Fp12` exports no generic
//!      `pow`, so this file carries a private `fp12Pow` — a constant-
//!      time square-and-multiply-always loop over `Fp12.square`/`.mul`
//!      (option 1 of `SPEC.md`'s "Known gap", recorded there; no
//!      `bls12_381` change).
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
//! ## Deliberately NOT in scope here
//!
//! The outer hybrid `age`-format envelope (`filippo.io/age`'s
//! recipient/identity stanzas, the armored `-----BEGIN AGE
//! ENCRYPTED FILE-----` framing, the `tle` CLI's file-level API) that
//! `drand/tlock` wraps THIS 128-byte `Ciphertext` inside of to encrypt
//! arbitrary-length payloads. This module implements the BF-IBE
//! primitive `tlock.go`'s `TimeLock`/`TimeUnlock` call directly (see
//! `ciphersuite.zig`'s `block_bytes` doc comment) — a hybrid envelope
//! on top is a natural, separable follow-up (`SPEC.md`'s "Out of
//! scope").

const std = @import("std");
const bls12_381 = @import("bls12_381");
const ciphersuite = @import("ciphersuite.zig");
const gate = @import("gate.zig");

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

    /// Inverse of `toBytes`. Does NOT subgroup-check `U` (same
    /// deserialization contract as `bls12_381.bls_sig.Signature.
    /// fromBytes` — see that type's doc comment); `decrypt` performs
    /// its own consistency check (`U == r*gen`) on every call, which is
    /// a STRONGER, scheme-specific check than a bare subgroup test, so
    /// no separate subgroup-check obligation is placed on callers here
    /// (unlike `bls_sig`'s verify family, which has no such recomputed-
    /// point check available). REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) g2.G2Error!Ciphertext {
        const u = try g2.fromBytesCompressed(bytes[0..g2.compressed_bytes].*);
        return .{
            .u = u,
            .v = bytes[g2.compressed_bytes..][0..block_bytes].*,
            .w = bytes[g2.compressed_bytes + block_bytes ..][0..block_bytes].*,
        };
    }
};

// ── private helpers: Gt (Fp12) exponentiation ───────────────────────

/// Constant-time select over `Fp12`: component-wise `Fp2.ctSelect`
/// (the same byte-mask merge `g1`/`g2`'s branchless point arithmetic
/// is built on) lifted through the `Fp6` tower level. Private helper
/// for `fp12Pow` — `bls12_381.Fp12` exports no select of its own, and
/// per this module's layering decision (`SPEC.md`'s "Known gap",
/// option 1 taken) the exponentiation machinery stays module-local
/// rather than reaching into the sibling.
fn fp12CtSelect(cond: bool, on_true: Fp12, on_false: Fp12) Fp12 {
    return .{
        .c0 = fp6CtSelect(cond, on_true.c0, on_false.c0),
        .c1 = fp6CtSelect(cond, on_true.c1, on_false.c1),
    };
}

fn fp6CtSelect(cond: bool, on_true: Fp6, on_false: Fp6) Fp6 {
    return .{
        .c0 = Fp2.ctSelect(cond, on_true.c0, on_false.c0),
        .c1 = Fp2.ctSelect(cond, on_true.c1, on_false.c1),
        .c2 = Fp2.ctSelect(cond, on_true.c2, on_false.c2),
    };
}

/// `base^exp` in `Gt`/`Fp12` — the `Gid^r` primitive `encrypt`'s step
/// 7 needs and `bls12_381.Fp12` does not export (`SPEC.md`'s "Known
/// gap"; option 1 — a module-local loop — taken, recorded there).
///
/// Construction: big-endian square-and-multiply-ALWAYS over `exp`'s
/// canonical 32-byte encoding, mirroring `g1`/`g2`'s
/// `scalarMulBytes` idiom exactly: every iteration performs one
/// `square` and one `mul` and merges via `fp12CtSelect`, so there is
/// no secret-dependent branch or memory access — `r = H3(sigma, M)`
/// is secret-derived (leaking it leaks `sigma`, hence the message),
/// so the exponent must be treated exactly like a secret scalar even
/// though this is "just" encryption-side randomness.
///
/// Correctness note: `exp` is a canonical `Fr` (< r, the order of the
/// `Gt` subgroup), so no reduction subtleties arise; `base` is always
/// a pairing output (an r-th-root-of-unity subgroup element), but the
/// loop is generic over any `Fp12` and never relies on that.
fn fp12Pow(base: Fp12, exp: Fr) Fp12 {
    var acc = Fp12.one;
    for (exp.toBytes()) |byte| {
        var bit: u3 = 7;
        while (true) : (bit -= 1) {
            acc = acc.square();
            const prod = acc.mul(base);
            acc = fp12CtSelect((byte >> bit) & 1 == 1, prod, acc);
            if (bit == 0) break;
        }
    }
    return acc;
}

/// Converts a `Gt` element from this module's CANONICAL pairing value
/// to the representation drand actually hashes — the element's CUBE.
///
/// **The interop finding this encodes (root-caused 2026-07-16, this
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
/// `fp12Pow`/`pairing` is exactly drand's `(Gid_kilic)^r`:
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
/// full 10-step construction this function transcribes
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
pub fn encrypt(p_pub: g2.Affine, round: u64, message: [block_bytes]u8, sigma: [block_bytes]u8) Ciphertext {
    // Steps 1-3: identity -> Qid -> Gid. `pairing.pairing` takes
    // `(G1, G2)` in exactly drand/kyber's `s.Pair(Qid, master)` order.
    const qid = ciphersuite.h1(ciphersuite.beaconId(round));
    const gid = pairing.pairing(qid, p_pub);

    // Step 5: r = H3(sigma, M) — the FO-transform binding scalar.
    const r = ciphersuite.h3(&sigma, &message);

    // Step 6: U = r * G2_generator (constant-time scalarMul).
    const u = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r).toAffine();

    // Step 7: gid_r = Gid^r — Gt exponentiation (see fp12Pow above).
    const gid_r = fp12Pow(gid, r);

    // Step 8: V = sigma XOR H2(gid_r) — hashed in drand's Gt
    // representation (the canonical value's cube; see gtToDrandRepr).
    var v = ciphersuite.h2(block_bytes, gtToDrandRepr(gid_r));
    for (&v, sigma) |*b, s| b.* ^= s;

    // Step 9: W = M XOR H4(sigma).
    var w = ciphersuite.h4(block_bytes, &sigma);
    for (&w, message) |*b, m| b.* ^= m;

    return .{ .u = u, .v = v, .w = w };
}

/// **FABLE CORE — REAL.** BF-IBE FullIdent decryption + the
/// Fiat-Shamir-Okamoto consistency check. See this file's module doc
/// comment for the full construction this function transcribes
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
pub fn decrypt(round_signature: g1.Affine, ct: Ciphertext) DecryptError![block_bytes]u8 {
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
    var sigma = ciphersuite.h2(block_bytes, gtToDrandRepr(gid_r));
    for (&sigma, ct.v) |*b, x| b.* ^= x;

    // Step 3: message = W XOR H4(sigma).
    var message = ciphersuite.h4(block_bytes, &sigma);
    for (&message, ct.w) |*b, x| b.* ^= x;

    // Step 4: FO/CCA consistency — recompute r' = H3(sigma, message)
    // and reject unless U == r' * G2_generator. Compare via the
    // canonical compressed encoding (unique for every point incl.
    // infinity), matching drand/kyber's `rP.Equal(c.U)`. The check's
    // outcome (accept/reject) is public, so a non-constant-time byte
    // compare is fine here; what must NOT happen is returning a
    // partially-decrypted message on mismatch.
    const r_check = ciphersuite.h3(&sigma, &message);
    const u_check = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r_check).toAffine();
    if (!std.mem.eql(u8, &g2.toBytesCompressed(u_check), &g2.toBytesCompressed(ct.u))) {
        return error.FoCheckFailed;
    }

    return message;
}

// ── tests: Ciphertext codec (REAL, ungated) ─────────────────────────

test "Ciphertext.encoded_bytes is 128 (96 G2 + 16 V + 16 W), matching drand's tlock.go wire format" {
    try std.testing.expectEqual(@as(usize, 128), Ciphertext.encoded_bytes);
}

test "Ciphertext.toBytes/fromBytes round-trip (generator U, arbitrary V/W)" {
    const ct: Ciphertext = .{
        .u = g2.Affine.generator,
        .v = [_]u8{0xab} ** block_bytes,
        .w = [_]u8{0xcd} ** block_bytes,
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
        .v = [_]u8{0} ** block_bytes,
        .w = [_]u8{0} ** block_bytes,
    }).toBytes();
    // Flip the compression-flag byte into an invalid combination: set
    // both the compressed bit and the infinity bit with a nonzero
    // x-coordinate tail present (same corruption idiom g1.zig/g2.zig's
    // own decode-rejection tests use) — set the top byte to something
    // that is not a valid flag combination.
    bytes[0] = 0xFF;
    try std.testing.expectError(error.InvalidEncoding, Ciphertext.fromBytes(bytes));
}

// ── tests: fp12Pow (private helper — algebraic self-consistency) ────
//
// encrypt/decrypt themselves are exercised by kat_test.zig (round-trip,
// tamper rejection, and the byte-exact drand interop vector — the
// arbiter for the Gt serialization). These tests pin fp12Pow's
// exponentiation LAW independently, against pairing bilinearity: the
// same identity encrypt/decrypt's correctness rests on.

test "fp12Pow: base^0 = 1, base^1 = base" {
    const gt = pairing.pairing(g1.Affine.generator, g2.Affine.generator);
    try std.testing.expect(fp12Pow(gt, bls12_381.Fr.zero).eql(Fp12.one));
    try std.testing.expect(fp12Pow(gt, bls12_381.Fr.one).eql(gt));
}

test "fp12Pow matches pairing bilinearity: e(P,Q)^r == e(rP,Q)" {
    // r = an arbitrary multi-bit scalar (exercises both set and unset
    // bits across several bytes of the big-endian encoding).
    var r_bytes = [_]u8{0} ** 32;
    r_bytes[28] = 0x01;
    r_bytes[29] = 0xf3;
    r_bytes[30] = 0x5a;
    r_bytes[31] = 0x8d;
    const r = Fr.fromBytes(r_bytes) catch unreachable;

    const gt = pairing.pairing(g1.Affine.generator, g2.Affine.generator);
    const lhs = fp12Pow(gt, r);

    const rp = g1.Jacobian.fromAffine(g1.Affine.generator).scalarMul(r).toAffine();
    const rhs = pairing.pairing(rp, g2.Affine.generator);
    try std.testing.expect(lhs.eql(rhs));
}

test "fp12Pow is multiplicative in the exponent: base^a * base^b == base^(a+b)" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 0x07;
    var b_bytes = [_]u8{0} ** 32;
    b_bytes[31] = 0x0b;
    var ab_bytes = [_]u8{0} ** 32;
    ab_bytes[31] = 0x12; // 7 + 11 = 18
    const a = Fr.fromBytes(a_bytes) catch unreachable;
    const b = Fr.fromBytes(b_bytes) catch unreachable;
    const ab = Fr.fromBytes(ab_bytes) catch unreachable;

    const gt = pairing.pairing(g1.Affine.generator, g2.Affine.generator);
    try std.testing.expect(fp12Pow(gt, a).mul(fp12Pow(gt, b)).eql(fp12Pow(gt, ab)));
}
