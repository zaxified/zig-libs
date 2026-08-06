// SPDX-License-Identifier: MIT

//! verify — BLS-verify a drand beacon round against its chain public key.
//!
//! ## Why a raw pairing check, not `bls12_381.bls_sig.verify`
//!
//! `bls12_381.bls_sig` implements the **minimal-pubkey-size /
//! ProofOfPossession** ciphersuite: public keys in `G1` (48 B),
//! signatures in `G2` (96 B), messages hashed to `G2` under the DST
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. drand's quicknet is the
//! MIRROR IMAGE — `bls-unchained-g1-rfc9380`: signatures in `G1` (48 B),
//! public key in `G2` (96 B), message hashed to `G1` under the RFC-9380
//! `..._NUL_` DST. The groups AND the DST differ, so `bls_sig.verify`
//! cannot verify a quicknet round. This module instead performs the same
//! verification equation drand's own `crypto.Scheme.VerifyBeacon` uses,
//! directly on `bls12_381.pairing`:
//!
//! ```
//! e(signature, G2_generator) == e(H1(beaconId(round)), public_key)
//! ```
//!
//! rearranged into a single multi-pairing product-is-identity check
//! (`pairingCheck`) with the second pairing's `G1` point negated. The
//! message hashing — `beaconId(round) = SHA-256(round_be)` and
//! `H1 = hashToCurveG1(·, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")`
//! — is REUSED verbatim from `tlock.ciphersuite` (this module and `tlock`
//! therefore can never drift on the quicknet scheme). No cryptography is
//! reimplemented here: every primitive comes from `bls12_381`/`tlock`.
//!
//! ## Randomness check
//!
//! drand defines a round's `randomness` as `SHA-256(signature)`. When the
//! round document carried a `randomness` field, `verifyRound` also
//! asserts that identity (`error.RandomnessMismatch` otherwise), so a
//! caller who trusts `randomness` downstream is protected against a
//! doc whose randomness was tampered independently of the signature.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const tlock = @import("tlock");

const chaininfo = @import("chaininfo.zig");
const round_mod = @import("round.zig");

const ChainInfo = chaininfo.ChainInfo;
const Round = round_mod.Round;

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;
const ciphersuite = tlock.ciphersuite;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const VerifyError = error{
    /// The chain's scheme is not one this module can verify (only
    /// quicknet `bls-unchained-g1-rfc9380` is supported).
    UnsupportedScheme,
    /// The `ChainInfo` and `Round` disagree on the signature group
    /// (e.g. a `G2`-signature chained round against a quicknet chain).
    SchemeGroupMismatch,
    /// The chain public key was not decoded (only populated for the
    /// supported scheme) — a `ChainInfo` for an unsupported scheme.
    MissingPublicKey,
    /// The round has no decodable `G1` signature point.
    MissingSignature,
    /// The pairing equation did not hold — the signature is not a valid
    /// threshold signature for this round under this chain key.
    InvalidSignature,
    /// `randomness != SHA-256(signature)` in the round document.
    RandomnessMismatch,
};

/// The BLS-verification equation for one quicknet round, on already-
/// decoded points. Returns whether
/// `e(sig, G2gen) == e(H1(beaconId(round)), pubkey)` holds.
///
/// This is the low-level core; `verifyRound` wraps it with scheme
/// dispatch and the `randomness` check. Exposed so a caller who already
/// holds decoded points (e.g. from `tlock`) can reuse the exact same
/// check `tlock`'s trust-boundary note points at.
pub fn verifyRoundPoints(pubkey: g2.Affine, round: u64, sig: g1.Affine) bool {
    // ⚠ Reject the identity on BOTH operands before pairing. A pairing with
    // an identity operand is the target-group identity, so with
    // `pubkey == 1` and `sig == 1` the equation degenerates to `1 == 1` and
    // this returned TRUE for every round — a total forgery of this
    // primitive. `verifyRound` happened to be safe only because
    // `chaininfo.parseInfo` rejects an identity-encoded public key upstream;
    // `round.parseRound` does not reject an identity signature, and this
    // function's own doc comment invites callers to skip both parsers. A
    // guard living in a caller is not a guard this function has.
    // Found by the 1A mutation audit.
    if (pubkey.infinity or sig.infinity) return false;

    // ⚠ Reject a signature that is on the curve but OUTSIDE the order-`r`
    // subgroup. The pairing equation below is blind to a cofactor-torsion
    // addend `T`: `e(T, Q)` has order dividing `gcd(ord(T), r) = 1`, so
    // `e(sig + T, Q) = e(sig, Q)` and the malleated `sig' = sig + T`
    // satisfies the same equation with different wire bytes. `parseRound`
    // rejects such a point at the parse boundary; this is the same guard
    // for the callers this function's doc comment invites to skip the
    // parser (a guard living in a caller is not a guard this function
    // has). The public key's subgroup membership is guaranteed by
    // `chaininfo.parseInfo`; a caller supplying a `g2.Affine` from
    // elsewhere must run `g2.Jacobian.fromAffine(pk).subgroupCheck()`
    // itself — the G2 check is ~2x the cost of this one and would be paid
    // on every beacon for a point this module's own parser has already
    // validated. Found by the wave-2 audit (W2-32).
    if (!g1.Jacobian.fromAffine(sig).subgroupCheck()) return false;

    const qid = ciphersuite.h1(ciphersuite.beaconId(round));
    const neg_qid = g1.Jacobian.fromAffine(qid).negate().toAffine();
    return pairing.pairingCheck(&.{
        .{ .p = sig, .q = g2.Affine.generator },
        .{ .p = neg_qid, .q = pubkey },
    });
}

/// Verify a parsed `Round` against a parsed `ChainInfo`. On success the
/// signature is a genuine threshold-BLS signature for `round.round` under
/// `info`'s chain key, AND (when present) the round's `randomness` equals
/// `SHA-256(signature)`. Any failure is a typed `VerifyError` — never a
/// panic or a silent false-accept.
pub fn verifyRound(info: *const ChainInfo, round: *const Round) VerifyError!void {
    if (!info.scheme.isVerifiable()) return error.UnsupportedScheme;
    const pubkey = info.pubkey_g2 orelse return error.MissingPublicKey;

    // A quicknet round's signature must be the 48-byte G1 element.
    if (round.sig_len != g1.compressed_bytes) return error.SchemeGroupMismatch;
    const sig = round.sig_g1 orelse return error.MissingSignature;

    if (!verifyRoundPoints(pubkey, round.round, sig)) return error.InvalidSignature;

    // drand: randomness = SHA-256(signature). Check it when present.
    if (round.randomness) |claimed| {
        var digest: [32]u8 = undefined;
        Sha256.hash(round.signatureBytes(), &digest, .{});
        if (!std.mem.eql(u8, &digest, &claimed)) return error.RandomnessMismatch;
    }
}

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

const quicknet_info_json =
    \\{
    \\  "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
    \\  "period": 3,
    \\  "genesis_time": 1692803367,
    \\  "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    \\  "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
    \\  "schemeID": "bls-unchained-g1-rfc9380",
    \\  "metadata": { "beaconID": "quicknet" }
    \\}
;

const round_1000_json =
    \\{
    \\  "round": 1000,
    \\  "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
    \\  "signature": "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"
    \\}
;

// A DIFFERENT chain's key: quicknet-t (testnet) master public key. A
// mainnet round must NOT verify against it.
const quicknet_t_info_json =
    \\{
    \\  "public_key": "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da",
    \\  "period": 3,
    \\  "genesis_time": 1689232296,
    \\  "hash": "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5",
    \\  "groupHash": "a81e9d63f614ccdb144b8ff149623dee7fb1d3fa64f7cbb2076b5136ad5b8f83",
    \\  "schemeID": "bls-unchained-g1-rfc9380",
    \\  "metadata": { "beaconID": "quicknet-t" }
    \\}
;

// ── THE KAT: genuine quicknet round-1000 verifies ──────────────────────

test "verifyRound: genuine quicknet round 1000 verifies against the chain key" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    try verifyRound(&info, &rnd);
}

test "verifyRound: the round-1000 randomness equals SHA-256(signature)" {
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    var digest: [32]u8 = undefined;
    Sha256.hash(rnd.signatureBytes(), &digest, .{});
    try testing.expectEqualSlices(u8, &digest, &rnd.randomness.?);
}

// ── negative tests: never a false accept ───────────────────────────────

test "verifyRound: a flipped signature byte is rejected (parse or verify), never accepted" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    // Same round, last signature nibble flipped 9→8.
    const bad_round =
        \\{"round":1000,"signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e38"}
    ;
    // ⚠ This used to be `… catch { return; }` — a bare `return` from a Zig
    // test body is a PASS, so once W2-32's subgroup check started
    // rejecting this input at parse time the test would have silently
    // stopped asserting anything. Assert the rejection instead.
    if (round_mod.parseRound(testing.allocator, bad_round)) |rnd| {
        try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
    } else |err| {
        try testing.expect(err == error.InvalidPoint or err == error.SignatureNotInSubgroup);
    }
}

test "verifyRound: correct signature but WRONG round number → InvalidSignature" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    // Round-1000's genuine signature, but the document claims round 1001.
    const wrong_round =
        \\{"round":1001,"signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    const rnd = try round_mod.parseRound(testing.allocator, wrong_round);
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
}

test "verifyRound: signature checked against a DIFFERENT chain key → InvalidSignature" {
    const other_info = try chaininfo.parseInfo(testing.allocator, quicknet_t_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    // Genuine mainnet round-1000 signature, verified against the TESTNET
    // chain key — must not validate.
    try testing.expectError(error.InvalidSignature, verifyRound(&other_info, &rnd));
}

test "verifyRound: tampered randomness (valid signature) → RandomnessMismatch" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    // Genuine signature, but randomness has its first nibble flipped.
    const bad_rnd =
        \\{"round":1000,"randomness":"0e290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    const rnd = try round_mod.parseRound(testing.allocator, bad_rnd);
    try testing.expectError(error.RandomnessMismatch, verifyRound(&info, &rnd));
}

test "verifyRound: quicknet chain info against a G2 (chained-shaped) round → SchemeGroupMismatch" {
    // Gap found by mutation testing: this branch had NO discriminating
    // test — disabling it left every test green (the code still errors,
    // just via the `MissingSignature` fallback instead of the specific
    // `SchemeGroupMismatch` this mismatch is supposed to report). A
    // realistic way to hit this: a caller fetches `/info` from a
    // verifiable (quicknet) chain but round data from a different,
    // chained-scheme beacon (96-byte G2 signature).
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const g2_shaped_round = "{\"round\":1000,\"signature\":\"" ++ ("ab" ** 96) ++ "\"}";
    const rnd = try round_mod.parseRound(testing.allocator, g2_shaped_round);
    try testing.expect(rnd.sig_g1 == null);
    try testing.expectError(error.SchemeGroupMismatch, verifyRound(&info, &rnd));
}

test "verifyRound: an unsupported (chained) scheme → UnsupportedScheme" {
    const chained =
        \\{"public_key":"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31","period":30,"genesis_time":1595431050,"hash":"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce","groupHash":"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a","schemeID":"pedersen-bls-chained","metadata":{"beaconID":"default"}}
    ;
    const info = try chaininfo.parseInfo(testing.allocator, chained);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    try testing.expectError(error.UnsupportedScheme, verifyRound(&info, &rnd));
}

// ── W2-32: cofactor-torsion malleation of a GENUINE signature ──────────
//
// The wave-2 audit demonstrated live that `verifyRound` ACCEPTED a forged
// round-1000 document whose signature was `sig + T` for a cofactor-torsion
// `T`, with `randomness` recomputed by the attacker so the
// `randomness == SHA-256(signature)` check passed too. This reconstructs
// that exact forgery from the torsion point (NOT from a random blob), so
// the test pins the property rather than an accident of some byte string.

/// `T = [r]·P` where `P` is the on-curve, NOT-in-`G1` point at `x = 4`.
/// Multiplying by the group order `r` annihilates the order-`r` component,
/// leaving a pure cofactor-torsion point: `ord(T) | h1` and
/// `gcd(h1, r) = 1`, hence `e(T, Q) ∈ μ_r` has order 1, i.e. `e(T, Q) = 1`.
/// By bilinearity `e(sig + T, Q) = e(sig, Q)` — the pairing equation
/// literally cannot distinguish the two.
fn cofactorTorsionPoint() !g1.Jacobian {
    var comp = [_]u8{0} ** g1.compressed_bytes;
    comp[0] = 0x80; // compression flag set, sort = 0
    comp[g1.compressed_bytes - 1] = 4;
    const p = try g1.fromBytesCompressed(comp);
    return g1.Jacobian.fromAffine(p).scalarMulBytes(&bls12_381.scalar.r_bytes);
}

test "W2-32: sig + cofactor-torsion is a different encoding the pairing alone cannot see" {
    const t = try cofactorTorsionPoint();
    // T is a real, non-trivial torsion point: on the curve, not O, not in G1.
    try testing.expect(!t.isIdentity());
    try testing.expect(t.isOnCurve());
    try testing.expect(!t.subgroupCheck());

    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    const mal = g1.Jacobian.fromAffine(rnd.sig_g1.?).add(t).toAffine();
    const mal_bytes = g1.toBytesCompressed(mal);

    // It really is a DIFFERENT 48-byte encoding for the SAME round…
    try testing.expect(!std.mem.eql(u8, &mal_bytes, rnd.signatureBytes()));
    // …and the raw pairing equation, on its own, still holds for it. This
    // is the assertion that makes the guards below load-bearing rather
    // than decorative: there is nothing in the equation to fail.
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const qid = ciphersuite.h1(ciphersuite.beaconId(rnd.round));
    const neg_qid = g1.Jacobian.fromAffine(qid).negate().toAffine();
    try testing.expect(pairing.pairingCheck(&.{
        .{ .p = mal, .q = g2.Affine.generator },
        .{ .p = neg_qid, .q = info.pubkey_g2.? },
    }));
}

test "W2-32: verifyRoundPoints REFUSES the malleated signature" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    const t = try cofactorTorsionPoint();
    const mal = g1.Jacobian.fromAffine(rnd.sig_g1.?).add(t).toAffine();

    // Control: the genuine point still verifies (the guard is not a blanket reject).
    try testing.expect(verifyRoundPoints(info.pubkey_g2.?, rnd.round, rnd.sig_g1.?));
    try testing.expect(!verifyRoundPoints(info.pubkey_g2.?, rnd.round, mal));
}

test "W2-32: the full public path refuses the forged round-1000 document" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    const t = try cofactorTorsionPoint();
    const mal_bytes = g1.toBytesCompressed(g1.Jacobian.fromAffine(rnd.sig_g1.?).add(t).toAffine());

    // The attacker recomputes randomness = SHA-256(sig') so that check
    // passes as well — exactly the document the audit got accepted.
    var digest: [32]u8 = undefined;
    Sha256.hash(&mal_bytes, &digest, .{});
    const forged = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"round\":1000,\"randomness\":\"{s}\",\"signature\":\"{s}\"}}",
        .{ std.fmt.bytesToHex(digest, .lower), std.fmt.bytesToHex(mal_bytes, .lower) },
    );
    defer testing.allocator.free(forged);

    // Rejected at the parse boundary…
    try testing.expectError(error.SignatureNotInSubgroup, round_mod.parseRound(testing.allocator, forged));

    // …and again by `verifyRound` for a `Round` a caller built by hand
    // (`Round` is a plain value type; nothing forces it through `parseRound`).
    var handmade = rnd;
    handmade.sig_bytes[0..mal_bytes.len].* = mal_bytes;
    handmade.sig_g1 = g1.Jacobian.fromAffine(rnd.sig_g1.?).add(t).toAffine();
    handmade.randomness = digest;
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &handmade));
}

// ── POSITIVE CONTROL: prove the test actually pins the scheme ──────────

/// Deliberately-broken beaconId: hashes the round LITTLE-endian instead
/// of big-endian. If the genuine KAT still verified under this, the test
/// would not actually be pinning drand's message construction.
fn brokenBeaconIdLE(round: u64) [32]u8 {
    var round_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_le, round, .little);
    var out: [32]u8 = undefined;
    Sha256.hash(&round_le, &out, .{});
    return out;
}

test "positive control: little-endian round hashing FAILS the genuine KAT (scheme is truly pinned)" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    const pubkey = info.pubkey_g2.?;
    const sig = rnd.sig_g1.?;

    // The CORRECT (big-endian) construction verifies:
    try testing.expect(verifyRoundPoints(pubkey, rnd.round, sig));

    // The BROKEN (little-endian) construction must NOT — proving the
    // big-endian round encoding is load-bearing, not incidental.
    const qid_broken = ciphersuite.h1(brokenBeaconIdLE(rnd.round));
    const neg = g1.Jacobian.fromAffine(qid_broken).negate().toAffine();
    const broken_ok = pairing.pairingCheck(&.{
        .{ .p = sig, .q = g2.Affine.generator },
        .{ .p = neg, .q = pubkey },
    });
    try testing.expect(!broken_ok);
}

// ── fuzz: parsers + verify path never panic / OOB / hang ───────────────

test "fuzz: chain-info + round parse and verify never panic on arbitrary input" {
    try std.testing.fuzz({}, fuzzParseVerify, .{});
}

fn fuzzParseVerify(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
    const input = buf[0..len];

    // Parsers must never crash and must bound allocation by the input.
    const maybe_info = chaininfo.parseInfo(testing.allocator, input) catch null;
    const maybe_round = round_mod.parseRound(testing.allocator, input) catch null;

    // If BOTH parsed, the verify path must also never crash (it will
    // almost always reject; the contract is "no panic", not "accepts").
    if (maybe_info) |info| {
        if (maybe_round) |rnd| {
            verifyRound(&info, &rnd) catch {};
        }
    }
}

test "verifyRoundPoints rejects identity operands (total-forgery guard)" {
    // Both operands identity => every pairing is the target-group identity,
    // so the equation was `1 == 1` and this returned true for ANY round.
    // The higher-level entry point was protected only by parseInfo's own
    // identity rejection, which is a different function's guard.
    try std.testing.expect(!verifyRoundPoints(g2.Affine.identity, 1, g1.Affine.identity));
    try std.testing.expect(!verifyRoundPoints(g2.Affine.identity, 12345, g1.Affine.identity));

    // Each alone must fail too — a caller could supply one legitimate point.
    try std.testing.expect(!verifyRoundPoints(g2.Affine.identity, 1, g1.Affine.generator));
    try std.testing.expect(!verifyRoundPoints(g2.Affine.generator, 1, g1.Affine.identity));
}
