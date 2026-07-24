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

test "verifyRound: a flipped signature byte → InvalidSignature" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    // Same round, last signature nibble flipped 9→8 (still a valid G1
    // point, just not the right one).
    const bad_round =
        \\{"round":1000,"signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e38"}
    ;
    const rnd = round_mod.parseRound(testing.allocator, bad_round) catch {
        // If the flipped bytes fail to decode as a point, that is also a
        // correct rejection (never a false accept) — the test's contract.
        return;
    };
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
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

test "verifyRound: an unsupported (chained) scheme → UnsupportedScheme" {
    const chained =
        \\{"public_key":"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31","period":30,"genesis_time":1595431050,"hash":"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce","groupHash":"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a","schemeID":"pedersen-bls-chained","metadata":{"beaconID":"default"}}
    ;
    const info = try chaininfo.parseInfo(testing.allocator, chained);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    try testing.expectError(error.UnsupportedScheme, verifyRound(&info, &rnd));
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
