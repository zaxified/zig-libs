// SPDX-License-Identifier: MIT

//! verify — BLS-verify a drand beacon round against its chain public key.
//!
//! ## Both schemes are standard BLS ciphersuites — verified through `bls12_381.scheme`
//!
//! drand's two live mainnet schemes are, byte for byte, two of the six
//! ciphersuites of draft-irtf-cfrg-bls-signature-05 in their **Basic**
//! (`_NUL_`) form, so this module verifies through
//! `bls12_381.scheme` and owns no pairing equation of its own:
//!
//! - **quicknet** — `bls-unchained-g1-rfc9380`: signatures in `G1`
//!   (48 B), public key in `G2` (96 B), message hashed to `G1` under
//!   `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`. That is
//!   `scheme.MinSigBasic`; the signed message is
//!   `beaconId(round) = SHA-256(u64be(round))`, REUSED from
//!   `tlock.ciphersuite` (so this module and `tlock` can never drift on
//!   quicknet; a comptime check pins `tlock`'s DST to the suite's).
//! - **the chained default network** — `pedersen-bls-chained` (chain hash
//!   `8990e7a9…b2ce`): public key in `G1` (48 B), signature in `G2`
//!   (96 B), message hashed to `G2` under the STANDARD RFC 9380
//!   `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. That is
//!   `scheme.MinPkBasic`. The signed digest folds in the previous round's
//!   signature — drand's `DigestBeacon` for this scheme:
//!   `m = SHA-256(previous_signature ‖ u64be(round))` (nothing written for
//!   an empty `previous_signature`). Source for the DST: drand/drand
//!   v2.1.7 `crypto/schemes.go` `NewPedersenBLSChained`
//!   (`bls.NewBLS12381SuiteWithDST(…G1…RO_NUL_, …G2…RO_NUL_)`, the comment
//!   there reads "default RFC9380 DST for G2"); confirmed by verifying three
//!   genuine default-chain beacons below, and by the positive control that
//!   the same beacons FAIL under the `_POP_` DST. (The non-RFC DST belongs
//!   to the deprecated `bls-unchained-on-g1`, which hashes to `G1` under
//!   the `G2` DST — still unverified here.)
//!
//! Until 2026-10-06 this file evaluated both equations directly on
//! `bls12_381.pairing`, because `bls12_381` then offered only the
//! min-pk / ProofOfPossession suite (`_POP_` DST), which verifies neither.
//! The suite's `verify` runs drand's `KeyValidate` on BOTH operands
//! (signature subgroup check; key non-identity + subgroup), which is what
//! the two guards here had been rebuilding by hand — with one gap: the
//! key's subgroup membership was left to `parseInfo`. It is now checked
//! on every call too (~0.17 ms for quicknet's `G2` key, ~0.12 ms for the
//! chained `G1` key, of a ~4.3 ms verification).
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
    /// The chain's scheme is not one this module can verify (quicknet
    /// `bls-unchained-g1-rfc9380` and the chained default network's
    /// `pedersen-bls-chained` are supported).
    UnsupportedScheme,
    /// The `ChainInfo` and `Round` disagree on the signature group
    /// (e.g. a `G2`-signature chained round against a quicknet chain, or
    /// a `G1`-signature quicknet round against the chained chain).
    SchemeGroupMismatch,
    /// The chain public key for the scheme's key group was not decoded —
    /// a hand-built `ChainInfo` (`parseInfo` always decodes it).
    MissingPublicKey,
    /// The round has no decoded signature point in the scheme's
    /// signature group — a hand-built `Round`.
    MissingSignature,
    /// The pairing equation did not hold — the signature is not a valid
    /// threshold signature for this round under this chain key.
    InvalidSignature,
    /// `randomness != SHA-256(signature)` in the round document.
    RandomnessMismatch,
};

/// The quicknet ciphersuite: draft-irtf-cfrg-bls-signature-05
/// min-signature-size, Basic — sig in `G1`, key in `G2`, `G1` `_NUL_` DST.
pub const QuicknetSuite = bls12_381.scheme.MinSigBasic;

/// The `pedersen-bls-chained` ciphersuite: min-pubkey-size, Basic — key in
/// `G1`, sig in `G2`, `G2` `_NUL_` DST.
pub const ChainedSuite = bls12_381.scheme.MinPkBasic;

comptime {
    // `beaconId`/`h1` come from `tlock.ciphersuite`; the hash-to-curve the
    // suite runs must be the one `tlock` decrypts under.
    std.debug.assert(std.mem.eql(u8, QuicknetSuite.dst_sig, ciphersuite.dst_g1));
}

/// The BLS verification of one quicknet round, on already-decoded points:
/// whether `sig` is a valid `QuicknetSuite` signature over
/// `beaconId(round)` under `pubkey`
/// (`e(sig, G2gen) == e(H1(beaconId(round)), pubkey)`).
///
/// This is the low-level core; `verifyRound` wraps it with scheme
/// dispatch and the `randomness` check. Exposed so a caller who already
/// holds decoded points (e.g. from `tlock`) can reuse the exact same
/// check `tlock`'s trust-boundary note points at.
///
/// Both operands get `KeyValidate` inside the suite: the identity is
/// refused (with both the identity the equation is `1 == 1` for every
/// round — found by the 1A mutation audit when this was a hand-written
/// pairing), and so is a point outside the order-`r` subgroup. For the
/// `G1` signature that check is the ONLY guard against malleation: the
/// pairing is blind to a cofactor-torsion addend `T` (`e(T, Q) = 1`), so
/// `sig + T` would satisfy the same equation with different wire bytes
/// (wave-2 audit W2-32). `parseInfo`/`parseRound` refuse all of these at
/// the parse boundary as well; the guards here are for callers who skip
/// the parsers.
pub fn verifyRoundPoints(pubkey: g2.Affine, round: u64, sig: g1.Affine) bool {
    const msg = ciphersuite.beaconId(round);
    return QuicknetSuite.verify(.{ .point = pubkey }, &msg, .{ .point = sig });
}

/// The DST `pedersen-bls-chained` hashes its digest to `G2` under: the
/// standard RFC 9380 `G2` `_NUL_` tag (drand/drand `crypto/schemes.go`,
/// `NewPedersenBLSChained`) — `ChainedSuite`'s. See the module doc comment.
pub const chained_dst = ChainedSuite.dst_sig;

comptime {
    std.debug.assert(std.mem.eql(u8, chained_dst, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"));
}

/// The 32-byte digest a `pedersen-bls-chained` round signs:
/// `SHA-256(previous_signature ‖ u64be(round))`, with nothing written for
/// an empty `previous_signature` (drand's `DigestBeacon`). Round 1 of the
/// default chain chains to the 32-byte genesis seed (the `groupHash`).
pub fn chainedMessage(round: u64, previous_signature: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(previous_signature);
    var round_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_be, round, .big);
    h.update(&round_be);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// The BLS verification of one `pedersen-bls-chained` round on
/// already-decoded points: whether `sig` is a valid `ChainedSuite`
/// signature over `chainedMessage(round, previous_signature)` under
/// `pubkey` (`e(pubkey, H2(m)) == e(G1gen, sig)`).
///
/// The same `KeyValidate` of both operands as `verifyRoundPoints`, one
/// group over. Unlike quicknet's `G1` case, a `G2` cofactor-torsion addend
/// is NOT known to pass the bare pairing (the ate pairing is bilinear only
/// on the order-`r` subgroup of `G2`, and the tested `sig + T` fails it);
/// the subgroup check still runs, so acceptance never depends on how the
/// Miller loop treats a point outside its domain. `parseInfo`/`parseRound`
/// already refuse all of these; the guards are for callers who skip them.
pub fn verifyChainedRoundPoints(pubkey: g1.Affine, round: u64, previous_signature: []const u8, sig: g2.Affine) bool {
    const msg = chainedMessage(round, previous_signature);
    return ChainedSuite.verify(.{ .point = pubkey }, &msg, .{ .point = sig });
}

/// Verify a parsed `Round` against a parsed `ChainInfo`. On success the
/// signature is a genuine threshold-BLS signature for `round.round` (and,
/// for the chained scheme, `round.previous_signature`) under `info`'s
/// chain key, AND (when present) the round's `randomness` equals
/// `SHA-256(signature)`. Any failure is a typed `VerifyError` — never a
/// panic or a silent false-accept.
///
/// For `pedersen-bls-chained` this verifies the round's own signature
/// over the `previous_signature` the document CLAIMS; it does not check
/// that the claim is the real previous round's signature. That is still
/// sound — the network signed `(previous_signature, round)` together, so
/// a forged `previous_signature` fails the equation — but a caller walking
/// the chain may also compare it with the round it verified before.
pub fn verifyRound(info: *const ChainInfo, round: *const Round) VerifyError!void {
    switch (info.scheme) {
        .unchained_g1_rfc9380 => {
            const pubkey = info.pubkey_g2 orelse return error.MissingPublicKey;
            // A quicknet round's signature must be the 48-byte G1 element.
            if (round.sig_len != g1.compressed_bytes) return error.SchemeGroupMismatch;
            const sig = round.sig_g1 orelse return error.MissingSignature;
            if (!verifyRoundPoints(pubkey, round.round, sig)) return error.InvalidSignature;
        },
        .pedersen_bls_chained => {
            const pubkey = info.pubkey_g1 orelse return error.MissingPublicKey;
            // A chained round's signature must be the 96-byte G2 element.
            if (round.sig_len != g2.compressed_bytes) return error.SchemeGroupMismatch;
            const sig = round.sig_g2 orelse return error.MissingSignature;
            if (!verifyChainedRoundPoints(pubkey, round.round, round.previousSignatureBytes(), sig))
                return error.InvalidSignature;
        },
        .bls_unchained_on_g1, .other => return error.UnsupportedScheme,
    }

    // drand: randomness = SHA-256(signature). Check it when present.
    if (round.randomness) |claimed| {
        var digest: [32]u8 = undefined;
        Sha256.hash(round.signatureBytes(), &digest, .{});
        if (!std.mem.eql(u8, &digest, &claimed)) return error.RandomnessMismatch;
    }
}

/// The round number a well-behaved drand node would be serving at wall-clock
/// time `now_unix`, per `info`'s `genesis_time`/`period_seconds` — drand's
/// own `chain.CurrentRound` formula (`drand/drand`, Go):
/// `floor((now - genesis_time) / period) + 1` for `now >= genesis_time`,
/// else round 1 (the chain has not started yet).
///
/// **What this does and does not prove.** `verifyRound` proves *authenticity*
/// — a genuine threshold signature over `round.round` under `info`'s chain
/// key — never *freshness*. Nothing in the signed bytes ties a round to the
/// moment it was fetched, so a malicious or compromised relay can replay an
/// old, genuinely-signed round forever and `verifyRound` accepts it every
/// time. A caller that needs liveness (e.g. using the beacon as a recent
/// randomness source, not just a historical one) must call this separately
/// and compare against the round it actually received — this module does
/// not do that comparison itself, since "how stale is too stale" is a
/// caller policy, not a verification fact.
///
/// Total: `parseInfo` refuses `period == 0` (`InvalidPeriod`), but a
/// `ChainInfo` is a plain value anyone can build, so a zero period here
/// answers 1 (the chain cannot have advanced) instead of dividing by zero
/// — SIGFPE in ReleaseFast, a panic in ReleaseSafe, before this guard —
/// and the `+ 1` saturates instead of wrapping to round 0, which exists on
/// no chain.
pub fn expectedRound(info: *const ChainInfo, now_unix: u64) u64 {
    if (now_unix < info.genesis_time) return 1;
    if (info.period_seconds == 0) return 1;
    return (now_unix - info.genesis_time) / info.period_seconds +| 1;
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

// A DIFFERENT chain's key: quicknet-t (testnet). A mainnet round must NOT
// verify against it. The live document lives in chaininfo.zig — an earlier
// copy here carried a groupHash that was not this chain's, which the
// chain-hash check now refuses (audit F8).
const quicknet_t_info_json = chaininfo.quicknet_t_info_json;

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

test "verifyRound: randomness is compared in FULL — a flip in the last or a middle byte is caught (audit F15)" {
    // The test above flips the first nibble, so a comparison weakened to
    // `digest[0..1]` still passed. These flip byte 31 and byte 15.
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const last =
        \\{"round":1000,"randomness":"fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fde","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    const r1 = try round_mod.parseRound(testing.allocator, last);
    try testing.expectError(error.RandomnessMismatch, verifyRound(&info, &r1));
    const middle =
        \\{"round":1000,"randomness":"fe290beca10872ef2fb164d2aa4442df4566183ec51c56ff3cd603d930e54fdd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    const r2 = try round_mod.parseRound(testing.allocator, middle);
    try testing.expectError(error.RandomnessMismatch, verifyRound(&info, &r2));
}

test "verifyRound: quicknet chain info against a G2 (chained) round → SchemeGroupMismatch" {
    // Gap found by mutation testing: this branch had NO discriminating
    // test — disabling it left every test green (the code still errors,
    // just via the `MissingSignature` fallback instead of the specific
    // `SchemeGroupMismatch` this mismatch is supposed to report). A
    // realistic way to hit this: a caller fetches `/info` from a
    // verifiable (quicknet) chain but round data from the chained default
    // beacon (96-byte G2 signature). Since 2026-10-06 that signature is a
    // genuine default-chain round (`parseRound` now decodes G2 and refuses
    // the junk bytes this test used before).
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    try testing.expect(rnd.sig_g1 == null);
    try testing.expectError(error.SchemeGroupMismatch, verifyRound(&info, &rnd));
}

test "verifyRound: chained chain info against a G1 (quicknet) round → SchemeGroupMismatch" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
    try testing.expectError(error.SchemeGroupMismatch, verifyRound(&info, &rnd));
}

test "verifyRound: hand-built values without the scheme's points → MissingPublicKey / MissingSignature" {
    var info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    var rnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    rnd.sig_g2 = null;
    try testing.expectError(error.MissingSignature, verifyRound(&info, &rnd));
    info.pubkey_g1 = null;
    try testing.expectError(error.MissingPublicKey, verifyRound(&info, &rnd));
}

test "verifyRound: an unsupported scheme (bls-unchained-on-g1, unknown) → UnsupportedScheme" {
    // The chained default document relabelled: the label is not hashed, so
    // it parses, and no point is decoded for a scheme this module does not
    // verify.
    for ([_][]const u8{ "bls-unchained-on-g1", "no-such-scheme" }) |label| {
        const doc = try std.mem.replaceOwned(u8, testing.allocator, chaininfo.chained_default_info_json, "pedersen-bls-chained", label);
        defer testing.allocator.free(doc);
        const info = try chaininfo.parseInfo(testing.allocator, doc);
        const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
        try testing.expectError(error.UnsupportedScheme, verifyRound(&info, &rnd));
        const crnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
        try testing.expectError(error.UnsupportedScheme, verifyRound(&info, &crnd));
    }
}

// ── expectedRound: freshness, not authenticity ──────────────────────────
//
// `verifyRound` only proves the signature is genuine for *some* round; it
// has no notion of "now" at all. These pin `expectedRound`'s formula
// (drand's own `chain.CurrentRound`) against the same quicknet chain used
// throughout this file, whose `genesis_time`/`period` (1692803367 / 3) are
// the real values fetched from the live quicknet `/info` endpoint.

test "expectedRound: at genesis_time exactly, the round is 1" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    try testing.expectEqual(@as(u64, 1), expectedRound(&info, info.genesis_time));
}

test "expectedRound: before genesis_time, the round is still 1 (chain has not started)" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    try testing.expectEqual(@as(u64, 1), expectedRound(&info, info.genesis_time - 1000));
}

test "expectedRound is total: period 0 answers 1 and the +1 saturates (audit F2)" {
    var info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    info.period_seconds = 0; // a hand-built ChainInfo; parseInfo itself refuses this
    try testing.expectEqual(@as(u64, 1), expectedRound(&info, 1757000000));
    info.period_seconds = 1;
    info.genesis_time = 0;
    try testing.expectEqual(std.math.maxInt(u64), expectedRound(&info, std.math.maxInt(u64)));
}

test "expectedRound: round 1000's own start instant round-trips to 1000, not 999 or 1001" {
    const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
    // Round n starts at genesis_time + (n - 1) * period and lasts one period.
    const round_1000_start = info.genesis_time + 999 * info.period_seconds;
    try testing.expectEqual(@as(u64, 1000), expectedRound(&info, round_1000_start));
    try testing.expectEqual(@as(u64, 1000), expectedRound(&info, round_1000_start + info.period_seconds - 1));
    try testing.expectEqual(@as(u64, 1001), expectedRound(&info, round_1000_start + info.period_seconds));
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
    const p = try g1.fromBytesCompressedUnchecked(comp);
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

// ── pedersen-bls-chained: the League of Entropy default network ───────
//
// EXTERNAL anchor: genuine beacons of the default chain (chain hash
// 8990e7a9…b2ce), not values this module computed. Provenance (recipe and
// the comparison against the live API in `tools/fetch_chained.py`):
//   - round 1 and round 1000000 (signature, previous_signature, randomness):
//     the test fixtures of thibmeu/drand-rs `drand_core` 0.0.19 (MIT,
//     `src/beacon.rs`), recorded there from
//     `curl https://drand.cloudflare.com/public/{1,1000000}`;
//   - round 2634945 (signature, previous_signature) and the public key:
//     drand/drand v2.1.7 (MIT/Apache-2.0) `crypto/schemes_test.go`
//     `TestVerifyBeacon`, which verifies them with drand's own Go scheme.
// The `/info` document is the live one `chaininfo.zig` already pins.
// api.drand.sh was not reachable from the session that committed these
// (egress policy), so `tools/fetch_chained.py` is the re-check against the
// live network, not the source.

const chained_info_json = chaininfo.chained_default_info_json;

/// Default-chain round 1: chains to the 32-byte genesis seed.
const chained_round_1_json =
    \\{"round":1,"randomness":"101297f1ca7dc44ef6088d94ad5fb7ba03455dc33d53ddb412bbc4564ed986ec","signature":"8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655","previous_signature":"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"}
;

const chained_round_1000000_json =
    \\{"round":1000000,"randomness":"a26ba4d229c666f52a06f1a9be1278dcc7a80dbc1dd2004a1ae7b63cb79fd37e","signature":"87e355169c4410a8ad6d3e7f5094b2122932c1062f603e6628aba2e4cb54f46c3bf1083c3537cd3b99e8296784f46fb40e090961cf9634f02c7dc2a96b69fc3c03735bc419962780a71245b72f81882cf6bb9c961bcf32da5624993bb747c9e5","previous_signature":"86bbc40c9d9347568967add4ddf6e351aff604352a7e1eec9b20dea4ca531ed6c7d38de9956ffc3bb5a7fabe28b3a36b069c8113bd9824135c3bff9b03359476f6b03beec179d4aeff456f4d34bbf702b9af78c3bb44e1892ace8e581bf4afa9"}
;

/// No `randomness` field: drand's Go test carries none, and a value we
/// computed would not be an anchor.
const chained_round_2634945_json =
    \\{"round":2634945,"signature":"814778ed1e480406beb43b74af71ce2f0373e0ea1bfdfea8f9ed62c876c20fcbc7f0163860e3da42ed2148756015f4551451898ffe06d384b4d002245025571b6b7a752f7158b40ad92b13b6d703ad31922a617f2c7f6d960b84d56cf1d79eef","previous_signature":"8bd96294383b4d1e04e736360bd7a487f9f409f1e7bd800b720656a310d577b3bdb1e1631af6c5782a1d8979c502f395036181eff4058960fc40bb7034cdae1991d3eda518ab204a077d2f7e724974cf87b407e549bd815cf0b8e5a3832f675d"}
;

test "verifyRound: genuine default-chain rounds 1, 1000000 and 2634945 verify (pedersen-bls-chained)" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    for ([_][]const u8{ chained_round_1_json, chained_round_1000000_json, chained_round_2634945_json }) |doc| {
        const rnd = try round_mod.parseRound(testing.allocator, doc);
        try verifyRound(&info, &rnd);
    }
}

test "chained: published randomness equals SHA-256(signature); round 1 chains to the genesis seed" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    for ([_][]const u8{ chained_round_1_json, chained_round_1000000_json }) |doc| {
        const rnd = try round_mod.parseRound(testing.allocator, doc);
        var digest: [32]u8 = undefined;
        Sha256.hash(rnd.signatureBytes(), &digest, .{});
        try testing.expectEqualSlices(u8, &digest, &rnd.randomness.?);
    }
    // drand's genesis seed is the groupHash: two independently published
    // documents agree on it.
    const r1 = try round_mod.parseRound(testing.allocator, chained_round_1_json);
    try testing.expectEqualSlices(u8, &info.group_hash, r1.previousSignatureBytes());
}

test "chained: a second chained network's genuine beacon verifies under its own key, not the default's" {
    // drand/drand v2.1.7 `TestVerifyBeacon`'s second pedersen-bls-chained
    // vector (a chain other than the default; key and beacon both from it).
    var pk_bytes: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk_bytes, "922a2e93828ff83345bae533f5172669a26c02dc76d6bf59c80892e12ab1455c229211886f35bb56af6d5bea981024df");
    const other_pk = try g1.fromBytesCompressed(pk_bytes);
    const rnd = try round_mod.parseRound(testing.allocator,
        \\{"round":3361396,"signature":"9904b4ec42e82cb42ad53f171cf0510a5eedff8b5e02e2db5a187489f7875307746998b9a6cf82130d291126d4b83cea1048c9b3f07a067e632c20391dc059d22d6a8e835f3980c8bd0183fb6df00a8fbbe6b8c9f61e888dfa76e12af4d4e355","previous_signature":"a2377f4e0403f0fd05f709a3292be1b2b59fe990a673ad7b7561b5bd5982b882a2378d36e39befb6ea3bb7aac113c50a18fb07aa4f9a59f95f1aaa7826dafbfcdbf22347c29996c294286fd11b402ad83edd83fa21fe6735fccb65785edbed47"}
    );
    try testing.expect(verifyChainedRoundPoints(other_pk, rnd.round, rnd.previousSignatureBytes(), rnd.sig_g2.?));
    // Cross-chain: the same beacon under the default chain's key, and a
    // default-chain beacon under the other key.
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
    const d = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    try testing.expect(!verifyChainedRoundPoints(other_pk, d.round, d.previousSignatureBytes(), d.sig_g2.?));
}

test "chained: tampered signature is refused (parse or verify)" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    // Last nibble 5 → 4, and a byte in the middle: both are typed refusals.
    for ([_][2][]const u8{ .{ "c9e5\",\"previous", "c9e4\",\"previous" }, .{ "87e355169c", "87e355169d" } }) |sub| {
        const doc = try std.mem.replaceOwned(u8, testing.allocator, chained_round_1000000_json, sub[0], sub[1]);
        defer testing.allocator.free(doc);
        try testing.expect(!std.mem.eql(u8, doc, chained_round_1000000_json));
        if (round_mod.parseRound(testing.allocator, doc)) |rnd| {
            try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
        } else |err| {
            try testing.expect(err == error.InvalidPoint or err == error.SignatureNotInSubgroup);
        }
    }
}

test "chained: genuine signature under the WRONG round → InvalidSignature" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    var rnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    for ([_]u64{ 999999, 1000001, 1000000 + (1 << 32) }) |r| {
        rnd.round = r;
        try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
    }
}

test "chained: tampered or missing previous_signature → InvalidSignature" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    const genuine = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    try verifyRound(&info, &genuine); // control
    // One byte of previous_signature flipped (first, middle, last).
    for ([_]usize{ 0, 47, 95 }) |i| {
        var rnd = genuine;
        rnd.previous_signature.?.bytes[i] ^= 0x01;
        try testing.expectError(error.InvalidSignature, verifyRound(&info, &rnd));
    }
    // Another round's previous_signature (round 2634945's).
    const other = try round_mod.parseRound(testing.allocator, chained_round_2634945_json);
    var swapped = genuine;
    swapped.previous_signature = other.previous_signature;
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &swapped));
    // Dropped: the message becomes SHA-256(round) alone.
    var dropped = genuine;
    dropped.previous_signature = null;
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &dropped));
    // Through the parser too: the round-1 genesis seed replaced.
    const doc = try std.mem.replaceOwned(u8, testing.allocator, chained_round_1_json, "176f93498eac", "176f93498ead");
    defer testing.allocator.free(doc);
    const r1 = try round_mod.parseRound(testing.allocator, doc);
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &r1));
}

test "chained: tampered randomness (valid signature) → RandomnessMismatch" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    const doc = try std.mem.replaceOwned(u8, testing.allocator, chained_round_1000000_json, "a26ba4d2", "a26ba4d3");
    defer testing.allocator.free(doc);
    const rnd = try round_mod.parseRound(testing.allocator, doc);
    try testing.expectError(error.RandomnessMismatch, verifyRound(&info, &rnd));
}

test "chained positive control: the DST and the message order are load-bearing" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    const pk = info.pubkey_g1.?;
    const sig = rnd.sig_g2.?;
    const neg_gen = g1.Jacobian.fromAffine(g1.Affine.generator).negate().toAffine();
    const Check = struct {
        fn holds(p: g1.Affine, ng: g1.Affine, s: g2.Affine, msg: []const u8, dst: []const u8) bool {
            const hm = bls12_381.hash_to_curve.hashToCurveG2(msg, dst);
            return pairing.pairingCheck(&.{ .{ .p = p, .q = hm }, .{ .p = ng, .q = s } });
        }
    };
    const msg = chainedMessage(rnd.round, rnd.previousSignatureBytes());
    // The construction verifyChainedRoundPoints uses holds…
    try testing.expect(Check.holds(pk, neg_gen, sig, &msg, chained_dst));
    // …the min-pubkey-size `_POP_` DST (`bls_sig`'s) does not…
    try testing.expect(!Check.holds(pk, neg_gen, sig, &msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"));
    // …the G1 tag does not…
    try testing.expect(!Check.holds(pk, neg_gen, sig, &msg, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"));
    // …and neither does the digest with round and previous signature swapped.
    var swapped: [32]u8 = undefined;
    var h = Sha256.init(.{});
    var round_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_be, rnd.round, .big);
    h.update(&round_be);
    h.update(rnd.previousSignatureBytes());
    h.final(&swapped);
    try testing.expect(!Check.holds(pk, neg_gen, sig, &swapped, chained_dst));
}

/// A pure `G2` cofactor-torsion point: `[r]·P` for an on-curve `P` outside
/// the order-`r` subgroup. `sig + T` is a different on-curve encoding of
/// "the signature plus something the order-`r` part cannot see".
fn g2CofactorTorsionPoint() !g2.Jacobian {
    var x: u8 = 1;
    while (x < 255) : (x += 1) {
        var comp = [_]u8{0} ** g2.compressed_bytes;
        comp[0] = 0x80;
        comp[g2.compressed_bytes - 1] = x;
        const pt = g2.fromBytesCompressedUnchecked(comp) catch continue;
        if (pt.infinity) continue;
        const j = g2.Jacobian.fromAffine(pt);
        if (!j.subgroupCheck()) return j.scalarMulBytes(&bls12_381.scalar.r_bytes);
    }
    return error.NoTorsionPointFound;
}

test "chained: sig + G2 cofactor torsion is refused at parse and by both verify entry points" {
    const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
    const rnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
    const t = try g2CofactorTorsionPoint();
    try testing.expect(!t.isIdentity());
    try testing.expect(!t.subgroupCheck());
    const mal = g2.Jacobian.fromAffine(rnd.sig_g2.?).add(t).toAffine();
    const mal_bytes = g2.toBytesCompressed(mal);
    try testing.expect(!std.mem.eql(u8, &mal_bytes, rnd.signatureBytes()));

    // Measured, and the difference from quicknet's W2-32 test: in G2 the
    // bare equation does NOT hold for sig + T (the ate pairing is bilinear
    // only on the order-r subgroup of G2), so here the subgroup guard is
    // defence in depth, not the only thing standing between T and an
    // accept. Pinned so a later reader does not reason from the G1 case.
    const msg = chainedMessage(rnd.round, rnd.previousSignatureBytes());
    const hm = bls12_381.hash_to_curve.hashToCurveG2(&msg, chained_dst);
    const neg_gen = g1.Jacobian.fromAffine(g1.Affine.generator).negate().toAffine();
    try testing.expect(!pairing.pairingCheck(&.{ .{ .p = info.pubkey_g1.?, .q = hm }, .{ .p = neg_gen, .q = mal } }));

    // The points-level primitive refuses it…
    try testing.expect(verifyChainedRoundPoints(info.pubkey_g1.?, rnd.round, rnd.previousSignatureBytes(), rnd.sig_g2.?));
    try testing.expect(!verifyChainedRoundPoints(info.pubkey_g1.?, rnd.round, rnd.previousSignatureBytes(), mal));

    // …the parser refuses the forged document (randomness recomputed)…
    var digest: [32]u8 = undefined;
    Sha256.hash(&mal_bytes, &digest, .{});
    const forged = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"round\":1000000,\"randomness\":\"{s}\",\"signature\":\"{s}\",\"previous_signature\":\"{s}\"}}",
        .{ std.fmt.bytesToHex(digest, .lower), std.fmt.bytesToHex(mal_bytes, .lower), std.fmt.bytesToHex(rnd.previous_signature.?.bytes, .lower) },
    );
    defer testing.allocator.free(forged);
    try testing.expectError(error.SignatureNotInSubgroup, round_mod.parseRound(testing.allocator, forged));

    // …and so does verifyRound for a hand-built Round.
    var handmade = rnd;
    handmade.sig_bytes = mal_bytes;
    handmade.sig_g2 = mal;
    handmade.randomness = digest;
    try testing.expectError(error.InvalidSignature, verifyRound(&info, &handmade));
}

test "verifyChainedRoundPoints rejects identity operands" {
    try testing.expect(!verifyChainedRoundPoints(g1.Affine.identity, 1, "", g2.Affine.identity));
    try testing.expect(!verifyChainedRoundPoints(g1.Affine.identity, 7, "abc", g2.Affine.identity));
}

test "chainedMessage: SHA-256(previous_signature ‖ u64be(round)), nothing written for an empty previous" {
    var expect: [32]u8 = undefined;
    Sha256.hash(&.{ 0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0x01, 0x02 }, &expect, .{});
    try testing.expectEqualSlices(u8, &expect, &chainedMessage(0x0102, &.{ 0xaa, 0xbb }));
    try testing.expectEqualSlices(u8, &ciphersuite.beaconId(1000), &chainedMessage(1000, ""));
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

test "ciphersuite.beaconId does not collapse the round's upper 32 bits (A1 F18)" {
    // `ciphersuite.beaconId` (tlock, shared with this module -- "so drand
    // and tlock can never drift on the scheme", root.zig) hashes the round
    // as a full big-endian u64. Nothing in this suite exercised a round
    // above 2^32 before this test: quicknet's real rounds top out around
    // 32 million (3 s/round, ~408 years from 2^32), and a mutation
    // truncating to the lower 32 bits (`round & 0xFFFF_FFFF`) left 42/42
    // tests green. `tlock`'s capsule format carries the round as a full
    // attacker-supplied u64, so two capsules differing only above bit 32
    // must NOT hash to the same beacon identity.
    const big_round: u64 = (@as(u64, 1) << 32) + 1000; // 4294968296
    const truncated_round: u64 = 1000; // what `round & 0xFFFF_FFFF` would collapse it to
    try testing.expect(!std.mem.eql(
        u8,
        &ciphersuite.beaconId(big_round),
        &ciphersuite.beaconId(truncated_round),
    ));
}

// ── fuzz: parsers + verify path never panic / OOB / hang ───────────────

// ⛔ This harness fetched its document and then threw it away. `smith.bytes`
// copies `min(buf.len, in.len)` octets and the `valueRangeAtMost` right after
// it reads EIGHT more as a little-endian u64, returning the range MINIMUM when
// fewer remain — so `len` was 0 for every input a corpus can carry and both
// parsers were handed `""` on every iteration. With no corpus, that empty
// document was the only input the harness ever ran: neither `/info` nor
// `/public/<round>` was parsed once inside it.
//
// ⛔ And the buffer was 512 octets against `quicknet_info_json`'s 504 — eight
// to spare, and `chaininfo.zig`'s own `quicknet_info_json ++ " trailing"`
// negative fixture is 513, i.e. over the buffer, which `Smith.slice` reads back
// as EMPTY rather than as a long seed. Raised to 2048 so
// the module's own documents and their damaged variants all fit.

/// The corpus-entry format `Smith.slice` reads (a little-endian u32 length,
/// then the frame). See `testkit/src/fuzz.zig` for the three hazards it carries.
const parseSeed = @import("testkit").fuzz.seed;

/// Whole JSON documents, in the format the length draw reads. Both parsers are
/// fed each one, which is the point: a `/public/<round>` document is a
/// structurally valid but semantically wrong `/info`, and vice versa, so every
/// seed exercises one accept path and one refusal.
const parse_seeds = [_][]const u8{
    parseSeed(quicknet_info_json), // the genuine quicknet /info
    parseSeed(chaininfo.quicknet_t_info_json), // a genuine SECOND chain (quicknet-t)
    parseSeed(
        \\{"public_key":"b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da","period":3,"genesis_time":1692803367,"hash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","groupHash":"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e","schemeID":"bls-unchained-g1-rfc9380","metadata":{"beaconID":"quicknet"}}
    ), // ⭐ quicknet's chain hash over quicknet-t's key: the audit-F1 ChainHashMismatch
    parseSeed(round_1000_json), // the genuine /public/1000
    parseSeed(quicknet_info_json ++ " trailing"), // ⭐ 513 octets: over the OLD 512 buffer, so it read back empty
    parseSeed(
        \\{"round": 1000, "signature": "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ), // a round with no randomness field: legal, the check is skipped
    parseSeed(
        \\{"round": 0, "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd", "signature": "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ), // round 0
    parseSeed(
        \\{"round": 18446744073709551615, "signature": "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ), // the u64 ceiling in the round number
    parseSeed(
        \\{"round": 1000, "signature": "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e3"}
    ), // an odd-length signature hex
    parseSeed(
        \\{"round": 1000, "signature": "ff4679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ), // 96 hex octets that are not a G1 point
    parseSeed(
        \\{"public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a", "period": 3, "genesis_time": 1692803367, "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e", "schemeID": "not-a-scheme"}
    ), // an /info whose schemeID this module does not implement
    parseSeed(
        \\{"public_key": "00", "period": 3, "genesis_time": 0, "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e", "schemeID": "bls-unchained-g1-rfc9380"}
    ), // a one-octet public key
    parseSeed("{" ++ "[" ** 200), // 200 levels of unbalanced nesting
    parseSeed("null"), // valid JSON that is not an object
    parseSeed("\x00\xff\xfe not json at all"), // non-UTF-8 bytes
    parseSeed(""), // the empty document: what the collapsed harness ran, every time
    parseSeed(chaininfo.chained_default_info_json), // the genuine chained default /info (G1 key)
    parseSeed(chained_round_1000000_json), // a genuine chained round (G2 signature)
};

test "fuzz: chain-info + round parse and verify never panic on arbitrary input" {
    try std.testing.fuzz({}, fuzzParseVerify, .{ .corpus = &parse_seeds });
}

fn fuzzParseVerify(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const input = buf[0..len];

    // Parsers must never crash and must bound allocation by the input.
    const maybe_info = chaininfo.parseInfo(testing.allocator, input) catch null;
    const maybe_round = round_mod.parseRound(testing.allocator, input) catch null;

    // If BOTH parsed, the verify path must also never crash (it will
    // almost always reject; the contract is "no panic", not "accepts").
    // ⚠ This never happened: see `fuzzVerifyRound` below for why.
    if (maybe_info) |info| {
        if (maybe_round) |rnd| {
            verifyRound(&info, &rnd) catch {};
        }
    }
}

test "corpus: every parse seed reaches a parser, and what each one decodes is pinned" {
    // ⭐ Not "no seed panicked": that read 100% while both parsers only ever
    // saw `""`. The numbers the empty document cannot produce are the decoded
    // G2 public key and the decoded G1 signature — the two points the whole
    // verify path stands on.
    var nonempty: usize = 0;
    var infos: usize = 0;
    var pubkeys_decoded: usize = 0;
    var rounds: usize = 0;
    var sigs_decoded: usize = 0;
    for (parse_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2048]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const input = buf[0..len];
        if (chaininfo.parseInfo(testing.allocator, input)) |info| {
            infos += 1;
            if (info.pubkey_g2 != null or info.pubkey_g1 != null) pubkeys_decoded += 1;
        } else |_| {}
        if (round_mod.parseRound(testing.allocator, input)) |rnd| {
            rounds += 1;
            if (rnd.sig_g1 != null or rnd.sig_g2 != null) sigs_decoded += 1;
        } else |_| {}
    }
    // One seed is deliberately the empty document.
    try testing.expectEqual(parse_seeds.len - 1, nonempty);
    // Measured 2026-09-07: every counter below was 0 before the draw was fixed.
    // 2026-10-06: +1 each for the chained /info and round seeds.
    try testing.expectEqual(@as(usize, 3), infos);
    try testing.expectEqual(@as(usize, 3), pubkeys_decoded);
    try testing.expectEqual(@as(usize, 5), rounds);
    try testing.expectEqual(@as(usize, 5), sigs_decoded);
}

// ── fuzz: the verify path itself, which the harness above cannot reach ────
//
// W2 A3 (F2) recorded that `verifyRound` — where this module's own CRIT
// (signature malleability / total forgery) lived — was never reached by the
// harness above, and the reason is structural rather than statistical. That
// harness draws ONE buffer of arbitrary octets and feeds the SAME buffer to
// both parsers, so reaching `verifyRound` would need a single document that is
// simultaneously a valid `/info` (six mandatory fields, a 64-hex `hash`, a
// 64-hex `groupHash`, and a 192-hex `public_key` that decodes to a G2 point
// passing KeyValidate) and a valid `/public/<round>` (a `round` number and a
// 96-hex `signature` that decodes to a G1 point in the subgroup). No such
// document exists — the two shapes disagree — so the `if (maybe_info) if
// (maybe_round)` body was dead code, and none of `verifyRoundPoints`, the
// subgroup guards, or the randomness check was ever fuzzed.
//
// This harness builds the two documents separately, from the genuine quicknet
// fixtures, and lets the fuzzer damage them the way a hostile responder would:
// nibbles of the key, of the signature, of the claimed randomness, the round
// number, the scheme label. Two assertions keep it honest in both directions:
// an undamaged pair MUST verify (so the harness cannot quietly stop reaching
// the verifier), and a pair whose crypto-relevant fields were damaged MUST NOT
// (which is the forgery property the CRIT was about).

const genuine_pubkey_hex = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const genuine_sig_hex = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";
const genuine_randomness_hex = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd";
const genuine_hash_hex = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
const genuine_group_hash_hex = "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e";
const genuine_scheme = "bls-unchained-g1-rfc9380";
const genuine_round: u64 = 1000;

/// Replaces up to three nibbles with fuzzer-chosen hex digits. Reports whether
/// the text actually changed — a flip that happens to write the digit already
/// there is not damage, and an unmeasured "it was damaged" flag is how a false
/// positive gets into a security assertion.
fn damageHex(smith: *std.testing.Smith, hex: []u8, original: []const u8) bool {
    if (hex.len == 0) return false;
    const n = smith.valueRangeAtMost(u8, 0, 3);
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        hex[smith.index(hex.len)] = "0123456789abcdef"[smith.valueRangeAtMost(u8, 0, 15)];
    }
    return !std.mem.eql(u8, hex, original);
}

/// What one fuzz iteration does to the genuine fixtures, decoded
/// DETERMINISTICALLY from a byte string (`fromBytes`) so that the same
/// function backs the fuzz harness and the plain tests below. The empty
/// string means "damage nothing" — the positive control — and that is
/// exactly the one input the runner feeds without `--fuzz`, so the
/// control runs on every ordinary gate run. (The previous harness drew
/// its choices through `Smith` scalar draws, whose out-of-range words are
/// replaced by the range MINIMUM, not discarded as its comment claimed;
/// the audit instrumented it: in 4 delivered calls neither assertion was
/// ever reachable.)
const Choices = struct {
    with_randomness: bool = true,
    wrong_round: bool = false,
    scheme_idx: u2 = 0,
    ops: [4]?Op = .{ null, null, null, null },

    const Op = struct { field: u3, index: u16, nibble: u8 };

    /// byte 0: flags (bit0 = no randomness, bit1 = wrong round, bits 2-3 =
    /// scheme index); then up to four 4-byte ops `[field, idx_lo, idx_hi, nibble]`.
    fn fromBytes(b: []const u8) Choices {
        var c: Choices = .{};
        if (b.len == 0) return c;
        c.with_randomness = b[0] & 1 == 0;
        c.wrong_round = b[0] & 2 != 0;
        c.scheme_idx = @truncate(b[0] >> 2);
        var i: usize = 1;
        var n: usize = 0;
        while (i + 4 <= b.len and n < c.ops.len) : ({
            i += 4;
            n += 1;
        }) {
            c.ops[n] = .{ .field = @truncate(b[i]), .index = std.mem.readInt(u16, b[i + 1 ..][0..2], .little), .nibble = b[i + 3] };
        }
        return c;
    }
};

/// Applies `ops` for `field` to `hex`; true iff the text actually changed
/// (writing the digit already there is not damage — an unmeasured "it was
/// damaged" flag is how a false positive gets into a security assertion).
fn applyDamage(c: *const Choices, field: u3, hex: []u8, original: []const u8) bool {
    for (c.ops) |maybe| {
        const op = maybe orelse continue;
        if (op.field != field or hex.len == 0) continue;
        hex[op.index % hex.len] = "0123456789abcdef"[op.nibble & 0xf];
    }
    return !std.mem.eql(u8, hex, original);
}

/// Build the two documents per `c`, parse, verify, and assert every verdict
/// the equation determines: parse failures where a hashed/keyed field was
/// altered, success on the intact pair, rejection of every damaged pair.
fn checkFixture(c: Choices) !void {
    var pk: [genuine_pubkey_hex.len]u8 = genuine_pubkey_hex.*;
    var sig: [genuine_sig_hex.len]u8 = genuine_sig_hex.*;
    var rand_hex: [genuine_randomness_hex.len]u8 = genuine_randomness_hex.*;
    var hash: [genuine_hash_hex.len]u8 = genuine_hash_hex.*;
    var ghash: [genuine_group_hash_hex.len]u8 = genuine_group_hash_hex.*;
    const pk_damaged = applyDamage(&c, 0, &pk, genuine_pubkey_hex);
    const sig_damaged = applyDamage(&c, 1, &sig, genuine_sig_hex);
    const rand_damaged = applyDamage(&c, 2, &rand_hex, genuine_randomness_hex);
    const hash_damaged = applyDamage(&c, 3, &hash, genuine_hash_hex);
    const ghash_damaged = applyDamage(&c, 4, &ghash, genuine_group_hash_hex);
    const scheme: []const u8 = switch (c.scheme_idx) {
        0 => genuine_scheme,
        1 => "pedersen-bls-chained",
        2 => "bls-unchained-on-g1",
        3 => "",
    };
    const round_no: u64 = if (c.wrong_round) genuine_round + 1 + @as(u64, c.scheme_idx) * 7919 else genuine_round;

    var info_buf: [768]u8 = undefined;
    const info_json = try std.fmt.bufPrint(
        &info_buf,
        "{{\"public_key\":\"{s}\",\"period\":3,\"genesis_time\":1692803367," ++
            "\"hash\":\"{s}\",\"groupHash\":\"{s}\",\"schemeID\":\"{s}\"," ++
            "\"metadata\":{{\"beaconID\":\"quicknet\"}}}}",
        .{ &pk, &hash, &ghash, scheme },
    );
    var round_buf: [512]u8 = undefined;
    const round_json = if (c.with_randomness)
        try std.fmt.bufPrint(&round_buf, "{{\"round\":{d},\"randomness\":\"{s}\",\"signature\":\"{s}\"}}", .{ round_no, &rand_hex, &sig })
    else
        try std.fmt.bufPrint(&round_buf, "{{\"round\":{d},\"signature\":\"{s}\"}}", .{ round_no, &sig });

    // The key, hash and groupHash are all inputs to the chain hash, so any
    // alteration of them must fail the parse. The scheme label is not
    // hashed, but `pedersen-bls-chained` KeyValidates a 48-byte G1 key, so
    // quicknet's 96-byte key under that label must fail too (since
    // 2026-10-06); under the other labels an untouched trio parses.
    const info_damaged = pk_damaged or hash_damaged or ghash_damaged or c.scheme_idx == 1;
    const info = chaininfo.parseInfo(testing.allocator, info_json) catch |e| {
        if (!info_damaged) return e; // fixture or parser drifted
        return;
    };
    if (info_damaged) return error.DamagedInfoParsed;

    const rnd = round_mod.parseRound(testing.allocator, round_json) catch |e| {
        if (!sig_damaged) return e;
        return; // a damaged signature may be refused at parse (usual) or reach verify (below)
    };

    const crypto_intact = !sig_damaged and (!c.with_randomness or !rand_damaged) and
        !c.wrong_round and c.scheme_idx == 0;
    if (verifyRound(&info, &rnd)) |_| {
        if (!crypto_intact) return error.DamagedRoundVerified;
    } else |_| {
        if (crypto_intact) return error.GenuineRoundRejected;
    }
}

test "fixture checks, deterministic: the positive control and one damage per field (audit F3)" {
    try checkFixture(.{}); // intact, with randomness → must verify
    try checkFixture(.{ .with_randomness = false });
    try checkFixture(.{ .wrong_round = true });
    try checkFixture(.{ .scheme_idx = 1 });
    try checkFixture(.{ .scheme_idx = 3 });
    // One nibble in each field, at a position that changes the text.
    try checkFixture(.{ .ops = .{ .{ .field = 1, .index = 95, .nibble = 0x8 }, null, null, null } }); // sig, last nibble
    try checkFixture(.{ .ops = .{ .{ .field = 2, .index = 63, .nibble = 0xe }, null, null, null } }); // randomness, last nibble
    try checkFixture(.{ .ops = .{ .{ .field = 0, .index = 191, .nibble = 0xb }, null, null, null } }); // key
    try checkFixture(.{ .ops = .{ .{ .field = 3, .index = 0, .nibble = 0x0 }, null, null, null } }); // hash
    try checkFixture(.{ .ops = .{ .{ .field = 4, .index = 10, .nibble = 0x1 }, null, null, null } }); // groupHash
}

test "fuzz: verifyRound on genuine and damaged quicknet documents" {
    try std.testing.fuzz({}, fuzzVerifyRound, .{ .corpus = &drand_seeds });
}

fn fuzzVerifyRound(_: void, smith: *std.testing.Smith) !void {
    var raw: [24]u8 = undefined;
    // One `smith.slice` draw; the empty input the default gate feeds decodes
    // to "damage nothing", i.e. the positive control runs every time.
    const n = smith.slice(&raw);
    try checkFixture(Choices.fromBytes(raw[0..n]));
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it -- 33 across 12
/// modules in three shapes -- each with its own note about the same trap (the
/// array has to be container-level or the returned slice dangles with the RIGHT
/// length and garbage behind it). It lives in `testkit.fuzz` now, with tests
/// that drive the real `std.testing.Smith` over what it produces.
const fuzzSeed = @import("testkit").fuzz.seed;

const drand_seeds = [_][]const u8{
    fuzzSeed(&.{}), // intact
    fuzzSeed(&.{0x01}), // no randomness
    fuzzSeed(&.{0x02}), // wrong round
    fuzzSeed(&.{0x04}), // chained scheme label
    fuzzSeed(&.{ 0x00, 1, 95, 0, 0x8 }), // signature nibble
    fuzzSeed(&.{ 0x00, 2, 63, 0, 0xe }), // randomness nibble
    fuzzSeed(&.{ 0x00, 0, 191, 0, 0xb }), // key nibble
    fuzzSeed(&.{ 0x00, 3, 5, 0, 0xf, 4, 7, 0, 0xa }), // hash + groupHash
};

// ── fuzz: the chained verify path on damaged default-chain documents ────
//
// The same shape as `checkFixture`, over the genuine default-chain /info
// and round 1000000. Fields: 0 key, 1 signature, 2 randomness, 3 hash,
// 4 groupHash, 5 previous_signature. Scheme labels: 0 the genuine
// `pedersen-bls-chained`, 1 quicknet's label (a 48-byte key under it must be
// refused at parse), 2 `bls-unchained-on-g1` and 3 "" (parse, unverifiable).

const chained_pubkey_hex = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
const chained_hash_hex = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";
const chained_group_hash_hex = "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a";
const chained_sig_hex = "87e355169c4410a8ad6d3e7f5094b2122932c1062f603e6628aba2e4cb54f46c3bf1083c3537cd3b99e8296784f46fb40e090961cf9634f02c7dc2a96b69fc3c03735bc419962780a71245b72f81882cf6bb9c961bcf32da5624993bb747c9e5";
const chained_prev_hex = "86bbc40c9d9347568967add4ddf6e351aff604352a7e1eec9b20dea4ca531ed6c7d38de9956ffc3bb5a7fabe28b3a36b069c8113bd9824135c3bff9b03359476f6b03beec179d4aeff456f4d34bbf702b9af78c3bb44e1892ace8e581bf4afa9";
const chained_randomness_hex = "a26ba4d229c666f52a06f1a9be1278dcc7a80dbc1dd2004a1ae7b63cb79fd37e";
const chained_round: u64 = 1000000;

fn checkChainedFixture(c: Choices) !void {
    var pk: [chained_pubkey_hex.len]u8 = chained_pubkey_hex.*;
    var sig: [chained_sig_hex.len]u8 = chained_sig_hex.*;
    var rand_hex: [chained_randomness_hex.len]u8 = chained_randomness_hex.*;
    var hash: [chained_hash_hex.len]u8 = chained_hash_hex.*;
    var ghash: [chained_group_hash_hex.len]u8 = chained_group_hash_hex.*;
    var prev: [chained_prev_hex.len]u8 = chained_prev_hex.*;
    const pk_damaged = applyDamage(&c, 0, &pk, chained_pubkey_hex);
    const sig_damaged = applyDamage(&c, 1, &sig, chained_sig_hex);
    const rand_damaged = applyDamage(&c, 2, &rand_hex, chained_randomness_hex);
    const hash_damaged = applyDamage(&c, 3, &hash, chained_hash_hex);
    const ghash_damaged = applyDamage(&c, 4, &ghash, chained_group_hash_hex);
    const prev_damaged = applyDamage(&c, 5, &prev, chained_prev_hex);
    const scheme: []const u8 = switch (c.scheme_idx) {
        0 => "pedersen-bls-chained",
        1 => genuine_scheme,
        2 => "bls-unchained-on-g1",
        3 => "",
    };
    const round_no: u64 = if (c.wrong_round) chained_round + 1 + @as(u64, c.scheme_idx) * 7919 else chained_round;

    var info_buf: [768]u8 = undefined;
    const info_json = try std.fmt.bufPrint(
        &info_buf,
        "{{\"public_key\":\"{s}\",\"period\":30,\"genesis_time\":1595431050," ++
            "\"hash\":\"{s}\",\"groupHash\":\"{s}\",\"schemeID\":\"{s}\"," ++
            "\"metadata\":{{\"beaconID\":\"default\"}}}}",
        .{ &pk, &hash, &ghash, scheme },
    );
    var round_buf: [768]u8 = undefined;
    const round_json = if (c.with_randomness)
        try std.fmt.bufPrint(&round_buf, "{{\"round\":{d},\"randomness\":\"{s}\",\"signature\":\"{s}\",\"previous_signature\":\"{s}\"}}", .{ round_no, &rand_hex, &sig, &prev })
    else
        try std.fmt.bufPrint(&round_buf, "{{\"round\":{d},\"signature\":\"{s}\",\"previous_signature\":\"{s}\"}}", .{ round_no, &sig, &prev });

    const info_damaged = pk_damaged or hash_damaged or ghash_damaged or c.scheme_idx == 1;
    const info = chaininfo.parseInfo(testing.allocator, info_json) catch |e| {
        if (!info_damaged) return e;
        return;
    };
    if (info_damaged) return error.DamagedInfoParsed;

    const rnd = round_mod.parseRound(testing.allocator, round_json) catch |e| {
        if (!sig_damaged) return e;
        return;
    };

    const crypto_intact = !sig_damaged and !prev_damaged and (!c.with_randomness or !rand_damaged) and
        !c.wrong_round and c.scheme_idx == 0;
    if (verifyRound(&info, &rnd)) |_| {
        if (!crypto_intact) return error.DamagedRoundVerified;
    } else |_| {
        if (crypto_intact) return error.GenuineRoundRejected;
    }
}

test "chained fixture checks, deterministic: the positive control and one damage per field" {
    try checkChainedFixture(.{}); // intact → must verify
    try checkChainedFixture(.{ .with_randomness = false });
    try checkChainedFixture(.{ .wrong_round = true });
    try checkChainedFixture(.{ .scheme_idx = 1 });
    try checkChainedFixture(.{ .scheme_idx = 2 });
    try checkChainedFixture(.{ .scheme_idx = 3 });
    try checkChainedFixture(.{ .ops = .{ .{ .field = 1, .index = 191, .nibble = 0x4 }, null, null, null } }); // sig, last nibble
    try checkChainedFixture(.{ .ops = .{ .{ .field = 2, .index = 63, .nibble = 0xf }, null, null, null } }); // randomness
    try checkChainedFixture(.{ .ops = .{ .{ .field = 0, .index = 95, .nibble = 0x0 }, null, null, null } }); // key
    try checkChainedFixture(.{ .ops = .{ .{ .field = 3, .index = 0, .nibble = 0x0 }, null, null, null } }); // hash
    try checkChainedFixture(.{ .ops = .{ .{ .field = 4, .index = 10, .nibble = 0x1 }, null, null, null } }); // groupHash
    try checkChainedFixture(.{ .ops = .{ .{ .field = 5, .index = 0, .nibble = 0x0 }, null, null, null } }); // previous_signature, first nibble
    try checkChainedFixture(.{ .ops = .{ .{ .field = 5, .index = 191, .nibble = 0x0 }, null, null, null } }); // previous_signature, last nibble
}

test "fuzz: verifyRound on genuine and damaged default-chain documents" {
    try std.testing.fuzz({}, fuzzVerifyChainedRound, .{ .corpus = &chained_seeds });
}

fn fuzzVerifyChainedRound(_: void, smith: *std.testing.Smith) !void {
    var raw: [24]u8 = undefined;
    const n = smith.slice(&raw);
    try checkChainedFixture(Choices.fromBytes(raw[0..n]));
}

const chained_seeds = [_][]const u8{
    fuzzSeed(&.{}), // intact
    fuzzSeed(&.{0x01}), // no randomness
    fuzzSeed(&.{0x02}), // wrong round
    fuzzSeed(&.{0x04}), // quicknet label over a G1 key
    fuzzSeed(&.{ 0x00, 1, 191, 0, 0x4 }), // signature nibble
    fuzzSeed(&.{ 0x00, 5, 7, 0, 0x3 }), // previous_signature nibble
    fuzzSeed(&.{ 0x00, 2, 63, 0, 0xf }), // randomness nibble
    fuzzSeed(&.{ 0x00, 0, 95, 0, 0x0 }), // key nibble
};

test "a chain key outside the order-r subgroup is refused by both points-level verifiers" {
    // Since 2026-10-06 the points-level verifiers run `KeyValidate` on the
    // key too (the suite's `verify`); before, only `parseInfo` did, and a
    // caller handing in a decoded key from elsewhere had to remember it.

    // Chained: key in G1. `pk + T` with `T` of G1 cofactor torsion pairs
    // exactly like `pk` (`e(T, Q) = 1`), so the bare equation HOLDS for a
    // genuine beacon under the malleated key — the key check is the only
    // thing refusing it. The old hand-written check accepted this.
    {
        const info = try chaininfo.parseInfo(testing.allocator, chained_info_json);
        const rnd = try round_mod.parseRound(testing.allocator, chained_round_1000000_json);
        const t = try cofactorTorsionPoint();
        const bad_pk = g1.Jacobian.fromAffine(info.pubkey_g1.?).add(t).toAffine();
        const msg = chainedMessage(rnd.round, rnd.previousSignatureBytes());
        const hm = bls12_381.hash_to_curve.hashToCurveG2(&msg, chained_dst);
        const neg_gen = g1.Jacobian.fromAffine(g1.Affine.generator).negate().toAffine();
        try testing.expect(pairing.pairingCheck(&.{ .{ .p = bad_pk, .q = hm }, .{ .p = neg_gen, .q = rnd.sig_g2.? } }));
        try testing.expect(verifyChainedRoundPoints(info.pubkey_g1.?, rnd.round, rnd.previousSignatureBytes(), rnd.sig_g2.?));
        try testing.expect(!verifyChainedRoundPoints(bad_pk, rnd.round, rnd.previousSignatureBytes(), rnd.sig_g2.?));
    }
    // quicknet: key in G2. Here the bare pairing already fails for `pk + T`
    // (measured for the chained G2 signature above); refused either way.
    {
        const info = try chaininfo.parseInfo(testing.allocator, quicknet_info_json);
        const rnd = try round_mod.parseRound(testing.allocator, round_1000_json);
        const t = try g2CofactorTorsionPoint();
        const bad_pk = g2.Jacobian.fromAffine(info.pubkey_g2.?).add(t).toAffine();
        try testing.expect(verifyRoundPoints(info.pubkey_g2.?, rnd.round, rnd.sig_g1.?));
        try testing.expect(!verifyRoundPoints(bad_pk, rnd.round, rnd.sig_g1.?));
    }
}

test "verifyRoundPoints rejects identity operands (total-forgery guard)" {
    // Both operands identity => every pairing is the target-group identity,
    // so the equation was `1 == 1` and this returned true for ANY round.
    // The higher-level entry point was protected only by parseInfo's own
    // identity rejection, which is a different function's guard.
    try std.testing.expect(!verifyRoundPoints(g2.Affine.identity, 1, g1.Affine.identity));
    try std.testing.expect(!verifyRoundPoints(g2.Affine.identity, 12345, g1.Affine.identity));

    // ⚠ A1 F16: these two calls do NOT pin the identity guard the way the
    // pair above does. Removing (mutation M07) or narrowing (M08) the
    // `pubkey.infinity or sig.infinity` check to only ONE side still passes
    // both assertions below, 42/42 green — because with a genuine
    // (non-identity) point on the other side, the pairing equation itself
    // already fails: `e(identity, G2gen) = 1` (target-group identity)
    // equals `e(qid, pubkey)` only if `pubkey` is ALSO identity (`qid` is
    // never identity for a real round number), and symmetrically for
    // `pubkey = identity, sig` genuine. There is no forged input this
    // one-sided half of the guard alone stops that the pairing check does
    // not already stop — it is pure defense-in-depth, verified redundant,
    // not an independently pinned property. Kept as a guard (since
    // 2026-10-06 it is `bls12_381.scheme`'s `KeyValidate`, which refuses an
    // identity key outright), but a test cannot honestly claim to enforce it.
    try std.testing.expect(!verifyRoundPoints(g2.Affine.identity, 1, g1.Affine.generator));
    try std.testing.expect(!verifyRoundPoints(g2.Affine.generator, 1, g1.Affine.identity));
}
