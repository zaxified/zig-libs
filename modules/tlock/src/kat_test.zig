// SPDX-License-Identifier: MIT

//! kat_test — the tlock known-answer harness.
//!
//! Two tiers (`CONVENTIONS.md`'s gate-flag discipline):
//!
//! 1. **REAL, UNGATED** (section 1 below): `ciphersuite.beaconId`/`h1`
//!    and `tlock.Ciphertext`'s byte codec, plus — the strongest check
//!    available WITHOUT the BF-IBE core — a byte-exact PAIRING sanity
//!    check against a GENUINE, live-fetched drand quicknet round: this
//!    proves `h1`'s DST/domain-separation and `beaconId`'s digest
//!    construction are correct against REAL production data, entirely
//!    using `bls12_381`'s own already-real `hash_to_curve`/`pairing`
//!    machinery — no IBE core needed at all (see that test's own
//!    comment for the exact identity checked).
//! 2. **GATE-GUARDED** (section 2 below): `encrypt`/`decrypt` round-trip
//!    and tamper-rejection tests. `gate.core_implemented` is now `true`
//!    (the cores are real), so these all RUN.
//! 3. **GATE-GUARDED drand interop vector** (section 3 below): a
//!    GENUINE ciphertext produced by drand's own Go `tle` CLI
//!    (extracted from `drand/tlock`'s `testdata/` age fixture),
//!    decrypted byte-exactly with the genuine published round
//!    signature, plus the byte-exact re-encryption of its recovered
//!    `(filekey, sigma)`. THIS is the check a self-consistent round
//!    trip can never provide — it caught a real interop divergence
//!    during implementation (drand/kilic's Gt values are the canonical
//!    pairing's CUBE — see `tlock.zig`'s `gtToDrandRepr`), exactly the
//!    failure mode the scaffold flagged in advance.
//!
//! ## Fixture-shape note (why the interop vector comes from an age file)
//!
//! `drand/tlock`'s repository ships no standalone byte-level IBE
//! vector — its Go tests round-trip through the full hybrid `age`
//! envelope, and `drand/kyber`'s `ibe_test.go` uses fresh random keys
//! per run (both fetched 2026-07-16). But the age envelope's `tlock`
//! STANZA body IS the raw 128-byte `(U,V,W)` this module targets, so
//! section 3's vector was extracted from a real committed `tle` fixture
//! and its expected plaintext (the age file key) independently verified
//! through the envelope's own HKDF/HMAC/AEAD chain — full provenance in
//! that section's comment and `NOTICE`.

const std = @import("std");
const tlock = @import("root.zig");
const ciphersuite = tlock.ciphersuite;
const gate = tlock.gate;
const bls12_381 = tlock.bls12_381;

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── genuine drand quicknet production data (fetched 2026-07-16) ─────
//
// Source: `https://api.drand.sh/v2/beacons/quicknet/info` (chain
// parameters) and `https://api.drand.sh/52db9ba7.../public/1000`
// (round 1000's signature) — see `SPEC.md`'s "Provenance" section for
// the exact URLs/response bodies. This is the SAME live League-of-
// Entropy quicknet beacon `drand/tlock`'s own `README.md` names as its
// production network.

/// quicknet's chain hash (`ChainHash()` — identifies which beacon a
/// ciphertext/signature belongs to; not consumed by this module's
/// hash/codec tests directly, recorded for `SPEC.md` cross-reference).
const quicknet_chain_hash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// quicknet's master public key, `G2` compressed (96 bytes) — `P_pub`.
const quicknet_pubkey_hex =
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183" ++
    "c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4b" ++
    "cb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece" ++
    "45a";

/// Round 1000's published threshold-BLS signature, `G1` compressed (48
/// bytes) — this IS the BF-IBE private key for identity
/// `ciphersuite.beaconId(1000)`.
const round_1000_sig_hex =
    "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb112" ++
    "5e342b73a8dd2bacbe47e4b6b63ed5e39";

fn quicknetPubkey() g2.Affine {
    return g2.fromBytesCompressed(hexBytes(96, quicknet_pubkey_hex)) catch unreachable;
}

fn round1000Signature() g1.Affine {
    return g1.fromBytesCompressed(hexBytes(48, round_1000_sig_hex)) catch unreachable;
}

// ── 1. REAL, UNGATED ──────────────────────────────────────────────────

test "quicknet chain hash / pubkey / round-1000 signature decode to valid, in-subgroup points" {
    try std.testing.expectEqual(@as(usize, 64), quicknet_chain_hash.len);

    const pk = quicknetPubkey();
    try std.testing.expect(!pk.infinity);
    try std.testing.expect(g2.Jacobian.fromAffine(pk).subgroupCheck());

    const sig = round1000Signature();
    try std.testing.expect(!sig.infinity);
    try std.testing.expect(g1.Jacobian.fromAffine(sig).subgroupCheck());
}

test "pairing sanity: e(round_1000_sig, G2_gen) == e(h1(beaconId(1000)), P_pub) — REAL quicknet data, no IBE core needed" {
    // This is the beacon-signature verification equation itself
    // (`bls12_381.bls_sig`'s verify shape, one tower level: min-pk-style
    // BLS but with G1 signatures against a G2 public key — quicknet's
    // own `crypto.Scheme.VerifyBeacon` checks exactly this), and it is
    // ALSO the precondition that makes `round_1000_sig` a valid BF-IBE
    // private key for `ciphersuite.h1(ciphersuite.beaconId(1000))`: if
    // this pairing check passes, `ciphersuite.h1`'s DST and
    // `ciphersuite.beaconId`'s digest construction are BOTH confirmed
    // correct against real, independently-published quicknet output —
    // entirely without needing `tlock.encrypt`/`decrypt` to exist yet.
    const p_pub = quicknetPubkey();
    const sig = round1000Signature();
    const qid = ciphersuite.h1(ciphersuite.beaconId(1000));

    const neg_qid = g1.Jacobian.fromAffine(qid).negate().toAffine();
    const ok = pairing.pairingCheck(&.{
        .{ .p = sig, .q = g2.Affine.generator },
        .{ .p = neg_qid, .q = p_pub },
    });
    try std.testing.expect(ok);
}

test "pairing sanity check FAILS for a wrong round (h1 domain separation actually matters)" {
    const p_pub = quicknetPubkey();
    const sig = round1000Signature();
    // Round 1001's identity, NOT 1000's — sig must not validate against it.
    const wrong_qid = ciphersuite.h1(ciphersuite.beaconId(1001));

    const neg_qid = g1.Jacobian.fromAffine(wrong_qid).negate().toAffine();
    const ok = pairing.pairingCheck(&.{
        .{ .p = sig, .q = g2.Affine.generator },
        .{ .p = neg_qid, .q = p_pub },
    });
    try std.testing.expect(!ok);
}

// ── 2. GATE-GUARDED ────────────────────────────────────────────────────

test "encrypt/decrypt round trip against a real quicknet round signature" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const p_pub = quicknetPubkey();
    const round: u64 = 1000;
    const sig = round1000Signature();

    const message = [_]u8{0x5a} ** ciphersuite.block_bytes;
    const sigma = [_]u8{0x11} ** ciphersuite.block_bytes;

    const ct = tlock.encrypt(p_pub, round, message, sigma);
    const recovered = try tlock.decrypt(sig, ct);
    try std.testing.expectEqualSlices(u8, &message, &recovered);
}

test "decrypt rejects a wrong round signature (FO consistency check fires)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const p_pub = quicknetPubkey();
    const message = [_]u8{0x5a} ** ciphersuite.block_bytes;
    const sigma = [_]u8{0x11} ** ciphersuite.block_bytes;

    // A signature for a DIFFERENT identity entirely (reuse the same
    // round-1000 signature but pretend it is for round 1001's
    // ciphertext) must fail the FO check, not silently decrypt.
    const ct_wrong_round = tlock.encrypt(p_pub, 1001, message, sigma);
    try std.testing.expectError(error.FoCheckFailed, tlock.decrypt(round1000Signature(), ct_wrong_round));
}

test "decrypt rejects a tampered ciphertext (V flipped)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const p_pub = quicknetPubkey();
    const message = [_]u8{0x5a} ** ciphersuite.block_bytes;
    const sigma = [_]u8{0x11} ** ciphersuite.block_bytes;
    var ct = tlock.encrypt(p_pub, 1000, message, sigma);
    ct.v[0] ^= 0xff;

    try std.testing.expectError(error.FoCheckFailed, tlock.decrypt(round1000Signature(), ct));
}

test "decrypt rejects a tampered ciphertext (W flipped)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const p_pub = quicknetPubkey();
    const message = [_]u8{0x5a} ** ciphersuite.block_bytes;
    const sigma = [_]u8{0x11} ** ciphersuite.block_bytes;
    var ct = tlock.encrypt(p_pub, 1000, message, sigma);
    ct.w[0] ^= 0xff;

    try std.testing.expectError(error.FoCheckFailed, tlock.decrypt(round1000Signature(), ct));
}

test "encrypt with a fixed sigma is deterministic (pins the ciphertext for a future byte-exact KAT)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const p_pub = quicknetPubkey();
    const message = [_]u8{0x5a} ** ciphersuite.block_bytes;
    const sigma = [_]u8{0x11} ** ciphersuite.block_bytes;

    const ct1 = tlock.encrypt(p_pub, 1000, message, sigma);
    const ct2 = tlock.encrypt(p_pub, 1000, message, sigma);
    try std.testing.expectEqualSlices(u8, &ct1.toBytes(), &ct2.toBytes());
}

// ── 3. drand interop vector (GATED — the Gt-serialization arbiter) ──
//
// A GENUINE ciphertext produced by drand's own Go implementation (the
// `tle` CLI), decrypted here byte-exactly — the ONE check a
// self-consistent round trip can never provide: it pins the exact Gt
// representation drand hashes for H2 (root-caused during this module's
// Fable pass: kilic/bls12-381's byte NESTING equals `Fp12.toBytes`, but
// its pairing VALUE is the canonical optimal-ate value's CUBE — see
// `tlock.zig`'s `gtToDrandRepr` and `SPEC.md`'s "Gt serialization"
// section; without the cube, this vector's FO check rejects).
//
// Provenance (all fetched 2026-07-16, recorded in `NOTICE`):
//
// - Ciphertext: `github.com/drand/tlock`, commit `7ceb44a598293f10c43d
//   2291df9e669c4251fe24`, `testdata/lorem-tle-testnet-quicknet-t-2024-
//   01-17-15-28.tle` — a real `tle`-armored age file encrypted by the
//   Go implementation to testnet beacon **quicknet-t** (chain hash
//   `cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5`,
//   scheme `"bls-unchained-g1-rfc9380"` — the IDENTICAL scheme to
//   mainnet quicknet, confirmed live via
//   `https://pl-us.testnet.drand.sh/<chainhash>/info`), round 5423142.
//   The 128-byte `(U,V,W)` below is that file's `tlock` stanza body
//   (base64-decoded from the age header — the raw BF-IBE ciphertext,
//   exactly this module's wire format).
// - Round signature: fetched live from
//   `https://pl-us.testnet.drand.sh/<chainhash>/public/5423142`; its
//   validity against the quicknet-t public key + this module's
//   `h1(beaconId(5423142))` is pinned by the UNGATED pairing-sanity
//   test below (same equation as the quicknet round-1000 test).
// - Expected plaintext (the age file key): recovered by THIS module's
//   `decrypt`, then INDEPENDENTLY verified outside Zig entirely: it
//   authenticates the fixture's age header (HKDF-SHA256 -> HMAC-SHA256
//   per the age v1 spec, byte-exact MAC match) and decrypts the
//   fixture's ChaCha20-Poly1305 payload to a plaintext byte-identical
//   to the same commit's `testdata/lorem.txt` — a full, independent
//   cryptographic binding of this 16-byte value to drand's Go
//   encryption (an HMAC/AEAD forgery being the only alternative).
// - `sigma`: the BF-IBE random pad the Go implementation drew when
//   producing the fixture — recovered via `V XOR H2(e(sig, U))` (the
//   decrypt path) and pinned so `encrypt` can be interop-tested
//   byte-exactly too, not just round-tripped.

/// quicknet-t (testnet) master public key, `G2` compressed — from the
/// live `/info` endpoint; matches the copy embedded in `drand/tlock`'s
/// own `tlock_test.go`.
const quicknet_t_pubkey_hex =
    "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1" ++
    "ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e" ++
    "6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f650" ++
    "2da";

/// The interop round `tle` encrypted the fixture to.
const interop_round: u64 = 5423142;

/// Round 5423142's published quicknet-t threshold-BLS signature (`G1`
/// compressed) — the BF-IBE private key for the fixture's identity.
const interop_round_sig_hex =
    "96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469d8556b36d2973a4" ++
    "f84681a45b1af2ce0511e5a32dd72508f";

/// The fixture's raw 128-byte BF-IBE ciphertext `U || V || W` (the age
/// `tlock` stanza body).
const interop_ct_hex =
    "87333e1baaf45ffafbaac29e472ae0974986e9d6028fb4b15cc470fdc7d4121" ++
    "31733f6c867c7bc56ed52b6ae85196b4b0d156e65ba0038b3c6521017b3aed0" ++
    "c45f31011db4a326cc75f4f4a8d78ded24715853d25d7acee2ee98a8a01d8b0" ++
    "d20868992a49bbb8dfa7756f8a804930fe58c997398f72fe8c72da3aab6984f" ++
    "2c9c";

/// The expected decrypt output: the age file key `tle` wrapped —
/// independently verified against the fixture's age header MAC and
/// payload (see the section comment above).
const interop_filekey_hex = "2088b21b7778175ecb9349dd98737373";

/// The BF-IBE `sigma` pad the Go implementation drew for the fixture
/// (recovered from the ciphertext itself; see the section comment).
const interop_sigma_hex = "7f4a8bfc5ae6e845ee01773a45dd92ae";

fn quicknetTPubkey() g2.Affine {
    return g2.fromBytesCompressed(hexBytes(96, quicknet_t_pubkey_hex)) catch unreachable;
}

fn interopRoundSignature() g1.Affine {
    return g1.fromBytesCompressed(hexBytes(48, interop_round_sig_hex)) catch unreachable;
}

test "interop vector provenance: quicknet-t round-5423142 signature verifies against the quicknet-t key (UNGATED)" {
    // e(sig, G2gen) == e(h1(beaconId(round)), P_pub) — proves the
    // live-fetched signature, the pubkey, and this module's
    // beaconId/h1 are all mutually consistent for the interop round,
    // using only bls12_381's already-real machinery (no IBE core).
    const sig = interopRoundSignature();
    const qid = ciphersuite.h1(ciphersuite.beaconId(interop_round));
    const neg_qid = g1.Jacobian.fromAffine(qid).negate().toAffine();
    try std.testing.expect(pairing.pairingCheck(&.{
        .{ .p = sig, .q = g2.Affine.generator },
        .{ .p = neg_qid, .q = quicknetTPubkey() },
    }));
}

test "drand interop: decrypt a genuine Go-tle-produced ciphertext byte-exactly (THE Gt-serialization arbiter)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const ct = try tlock.Ciphertext.fromBytes(hexBytes(128, interop_ct_hex));
    const filekey = try tlock.decrypt(interopRoundSignature(), ct);
    try std.testing.expectEqualSlices(u8, &hexBytes(16, interop_filekey_hex), &filekey);
}

test "drand interop: re-encrypting the recovered (filekey, sigma) reproduces the Go ciphertext byte-exactly" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const ct = tlock.encrypt(
        quicknetTPubkey(),
        interop_round,
        hexBytes(16, interop_filekey_hex),
        hexBytes(16, interop_sigma_hex),
    );
    try std.testing.expectEqualSlices(u8, &hexBytes(128, interop_ct_hex), &ct.toBytes());
}

test "drand interop: the fixture rejects under a mismatched round signature (FO check, cross-beacon)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    // The mainnet quicknet round-1000 signature is a perfectly valid
    // G1 point — but not the private key for THIS ciphertext's
    // identity, so decrypt must reject, never emit a wrong file key.
    const ct = try tlock.Ciphertext.fromBytes(hexBytes(128, interop_ct_hex));
    try std.testing.expectError(error.FoCheckFailed, tlock.decrypt(round1000Signature(), ct));
}
