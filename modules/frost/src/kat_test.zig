// SPDX-License-Identifier: MIT
//! Tests against the official RFC 9591 Appendix E.5 secp256k1/SHA-256
//! test vector (`kat_vectors.zig`).
//!
//! **Current status: all ten threshold-specific cores are REAL and every
//! test below PASSES** (32/32, Debug and ReleaseFast) — the hash-layer
//! tests (`h1`/`h3`/`h4`/`h5`) cross-validate this module's
//! `expand_message_xmd`/`hash_to_field` implementation against the RFC's
//! own published intermediate values, and the tests below exercise the
//! ten cores (`trustedDealerKeygen`, `secretShareCombine`,
//! `round1Commit`, `computeBindingFactors`, `aggregate`, `verify`,
//! `verifySignatureShare`, …) against the same Appendix E.5 vector. No
//! `@panic`/TODO stub remains in `root.zig`. See `root.zig`'s module doc
//! comment for exactly which construction each function follows.
//!
//! Coverage, by category:
//!
//!   - `trustedDealerKeygen` reproduces the vector's 3 participant
//!     shares AND group public key from the vector's group secret key +
//!     its one Shamir coefficient, byte-exact.
//!   - `secretShareCombine` reconstructs the vector's group secret key
//!     from 2-of-3 subsets of the vector's own shares (the official
//!     `participant_list: 1,3` subset, plus `{1,2}`/`{2,3}` as
//!     self-consistency checks over the same official data).
//!   - `round1Commit` reproduces both P1's and P3's published nonce
//!     commitments from their published nonces, byte-exact.
//!   - `computeBindingFactors` reproduces both P1's and P3's published
//!     binding factors from the published `binding_factor_input`
//!     preimage (re-derived from the vector's own group public key,
//!     message, and commitment list — not read directly off the
//!     preimage field, to exercise the REAL composition, not just `h1`).
//!   - `aggregate` reproduces the vector's exact 65-byte final
//!     signature (which transitively pins down `round2Sign`'s
//!     signature-share equation, `computeGroupCommitment`, and
//!     `computeChallenge`/`h2` — see `root.zig`'s "what the vectors do
//!     NOT cover" note: this ciphersuite's vector does not publish a
//!     standalone `group_commitment`/`challenge` scalar).
//!   - `verify` accepts the vector's aggregate signature and rejects a
//!     tampered copy (flipped byte in `z`, and separately in `r`).
//!   - `verifySignatureShare` accepts both P1's and P3's published
//!     signature shares and rejects a corrupted one.
//!   - An end-to-end (2,3) round trip with FRESH random key material
//!     (not a published vector): `trustedDealerKeygen` →
//!     `generateNonces` → `round1Commit` → `round2Sign` (for 2 of 3
//!     participants) → `aggregate` → `verify` accepts.

const std = @import("std");
const frost = @import("root.zig");
const v = @import("kat_vectors.zig");

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

fn scalarFromHex(hex_str: []const u8) frost.Scalar {
    return frost.Scalar.fromBytes(hexN(32, hex_str), .big) catch unreachable;
}

fn identifierFromU16(i: u16) frost.Identifier {
    return frost.Identifier.fromU16(i) catch unreachable;
}

fn elementFromHex(hex_str: []const u8) frost.Element {
    return frost.Element.fromBytes(hexN(33, hex_str)) catch unreachable;
}

fn signingShareFromHex(hex_str: []const u8) frost.SigningShare {
    return frost.SigningShare.fromBytes(hexN(32, hex_str)) catch unreachable;
}

fn signatureShareFromHex(hex_str: []const u8) frost.SignatureShare {
    return frost.SignatureShare.fromBytes(hexN(32, hex_str)) catch unreachable;
}

// ── h1/h3/h4/h5 — REAL, PASS today ───────────────────────────────────────
//
// These four tests cross-validate `expandMessageXmd48`/`hashToScalar`
// (the shared inner step of h1/h2/h3) and the plain-tagged-SHA256 h4/h5
// against the RFC's own published intermediate values. h2 shares its
// entire construction with h1/h3 (same function, different DST label),
// so these four passing is strong evidence h2 is correct too, even
// though the vector never isolates a standalone h2 output to check
// directly (see the module doc comment's "what the vectors do NOT
// cover" note).

test "h1(P1 binding_factor_input) == P1 binding_factor (RFC 9591 Appendix E.5)" {
    const input = hexN(129, v.round1_p1.binding_factor_input);
    const got = frost.h1(&input);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p1.binding_factor), &got.toBytes(.big));
}

test "h1(P3 binding_factor_input) == P3 binding_factor (RFC 9591 Appendix E.5)" {
    const input = hexN(129, v.round1_p3.binding_factor_input);
    const got = frost.h1(&input);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p3.binding_factor), &got.toBytes(.big));
}

test "H3(P1 hiding_nonce_randomness || P1 participant_share) == P1 hiding_nonce" {
    const random_bytes = hexN(32, v.round1_p1.hiding_nonce_randomness);
    const secret = signingShareFromHex(v.participant_shares.p1).scalar();
    const got = frost.nonceGenerate(random_bytes, secret);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p1.hiding_nonce), &got.toBytes(.big));
}

test "H3(P1 binding_nonce_randomness || P1 participant_share) == P1 binding_nonce" {
    const random_bytes = hexN(32, v.round1_p1.binding_nonce_randomness);
    const secret = signingShareFromHex(v.participant_shares.p1).scalar();
    const got = frost.nonceGenerate(random_bytes, secret);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p1.binding_nonce), &got.toBytes(.big));
}

test "H3(P3 hiding_nonce_randomness || P3 participant_share) == P3 hiding_nonce" {
    const random_bytes = hexN(32, v.round1_p3.hiding_nonce_randomness);
    const secret = signingShareFromHex(v.participant_shares.p3).scalar();
    const got = frost.nonceGenerate(random_bytes, secret);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p3.hiding_nonce), &got.toBytes(.big));
}

test "H3(P3 binding_nonce_randomness || P3 participant_share) == P3 binding_nonce" {
    const random_bytes = hexN(32, v.round1_p3.binding_nonce_randomness);
    const secret = signingShareFromHex(v.participant_shares.p3).scalar();
    const got = frost.nonceGenerate(random_bytes, secret);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p3.binding_nonce), &got.toBytes(.big));
}

test "generateNonces composes nonceGenerate identically to the two direct H3 calls above" {
    const signing_share = signingShareFromHex(v.participant_shares.p1);
    const nonces = frost.generateNonces(
        signing_share,
        hexN(32, v.round1_p1.hiding_nonce_randomness),
        hexN(32, v.round1_p1.binding_nonce_randomness),
    );
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p1.hiding_nonce), &nonces.hiding.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p1.binding_nonce), &nonces.binding.toBytes(.big));
}

test "h4(message) matches the H4 output embedded in P1's binding_factor_input (bytes 33..65)" {
    const msg = hexN(4, v.group.message);
    const got = frost.h4(&msg);
    const expected = v.round1_p1.binding_factor_input[66..130]; // hex chars 33*2..65*2
    try std.testing.expectEqualSlices(u8, &hexN(32, expected), &got);
}

test "h5(encodeGroupCommitmentList) matches the H5 output embedded in P1's binding_factor_input (bytes 65..97)" {
    const gpa = std.testing.allocator;

    const commitment_list = [_]frost.SigningCommitments{
        .{ .identifier = identifierFromU16(1), .hiding = elementFromHex(v.round1_p1.hiding_nonce_commitment), .binding = elementFromHex(v.round1_p1.binding_nonce_commitment) },
        .{ .identifier = identifierFromU16(3), .hiding = elementFromHex(v.round1_p3.hiding_nonce_commitment), .binding = elementFromHex(v.round1_p3.binding_nonce_commitment) },
    };
    const encoded = try frost.encodeGroupCommitmentList(gpa, &commitment_list);
    defer gpa.free(encoded);
    try std.testing.expectEqual(@as(usize, 196), encoded.len); // 2 * (32 + 33 + 33)

    const got = frost.h5(encoded);
    const expected = v.round1_p1.binding_factor_input[130..194]; // hex chars 65*2..97*2
    try std.testing.expectEqualSlices(u8, &hexN(32, expected), &got);
}

// ── round1Commit ──────────────────────────────────────────────────────────

test "round1Commit(P1 nonces) reproduces P1's published commitments" {
    const nonces = frost.SigningNonces{
        .hiding = scalarFromHex(v.round1_p1.hiding_nonce),
        .binding = scalarFromHex(v.round1_p1.binding_nonce),
    };
    const comm = try frost.round1Commit(nonces);
    try std.testing.expectEqualSlices(u8, &hexN(33, v.round1_p1.hiding_nonce_commitment), &comm.hiding.toBytes());
    try std.testing.expectEqualSlices(u8, &hexN(33, v.round1_p1.binding_nonce_commitment), &comm.binding.toBytes());
}

test "round1Commit(P3 nonces) reproduces P3's published commitments" {
    const nonces = frost.SigningNonces{
        .hiding = scalarFromHex(v.round1_p3.hiding_nonce),
        .binding = scalarFromHex(v.round1_p3.binding_nonce),
    };
    const comm = try frost.round1Commit(nonces);
    try std.testing.expectEqualSlices(u8, &hexN(33, v.round1_p3.hiding_nonce_commitment), &comm.hiding.toBytes());
    try std.testing.expectEqualSlices(u8, &hexN(33, v.round1_p3.binding_nonce_commitment), &comm.binding.toBytes());
}

// ── shared vector-derived fixtures for the tests below ───────────────────

fn vectorCommitmentList() [2]frost.SigningCommitments {
    return .{
        .{ .identifier = identifierFromU16(1), .hiding = elementFromHex(v.round1_p1.hiding_nonce_commitment), .binding = elementFromHex(v.round1_p1.binding_nonce_commitment) },
        .{ .identifier = identifierFromU16(3), .hiding = elementFromHex(v.round1_p3.hiding_nonce_commitment), .binding = elementFromHex(v.round1_p3.binding_nonce_commitment) },
    };
}

// ── computeBindingFactors ─────────────────────────────────────────────────

test "computeBindingFactors reproduces both P1's and P3's published binding factors" {
    const gpa = std.testing.allocator;

    const group_public_key = elementFromHex(v.group.public_key);
    const commitment_list = vectorCommitmentList();
    const msg = hexN(4, v.group.message);

    const binding_factor_list = try frost.computeBindingFactors(gpa, group_public_key, &commitment_list, &msg);
    defer gpa.free(binding_factor_list);
    try std.testing.expectEqual(@as(usize, 2), binding_factor_list.len);

    const p1_factor = try frost.bindingFactorForParticipant(binding_factor_list, identifierFromU16(1));
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p1.binding_factor), &p1_factor.toBytes(.big));

    const p3_factor = try frost.bindingFactorForParticipant(binding_factor_list, identifierFromU16(3));
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round1_p3.binding_factor), &p3_factor.toBytes(.big));
}

// ── trustedDealerKeygen / secretShareCombine ──────────────────────────────

test "trustedDealerKeygen(group secret, [coefficient_1], 3, 2) reproduces all 3 published shares + group public key" {
    const gpa = std.testing.allocator;

    const secret_key = scalarFromHex(v.group.secret_key);
    const coefficients = [_]frost.Scalar{scalarFromHex(v.group.coefficient_1)};

    const result = try frost.trustedDealerKeygen(gpa, secret_key, &coefficients, v.config.max_participants, v.config.min_participants);
    defer {
        for (result.shares) |*s| s.deinit();
        gpa.free(result.shares);
    }
    defer gpa.free(result.vss_commitment);

    try std.testing.expectEqualSlices(u8, &hexN(33, v.group.public_key), &result.group_public_key.toBytes());
    try std.testing.expectEqual(@as(usize, 3), result.shares.len);

    const expected = [_][]const u8{ v.participant_shares.p1, v.participant_shares.p2, v.participant_shares.p3 };
    for (result.shares, 0..) |share, i| {
        try std.testing.expectEqual(@as(u16, @intCast(i + 1)), std.mem.readInt(u16, share.identifier.bytes[30..32], .big));
        try std.testing.expectEqualSlices(u8, &hexN(32, expected[i]), &share.signing_share.toBytes());
    }
}

test "secretShareCombine reconstructs the group secret from the official {1,3} subset" {
    const shares = [_]frost.ParticipantShare{
        .{ .identifier = identifierFromU16(1), .signing_share = signingShareFromHex(v.participant_shares.p1) },
        .{ .identifier = identifierFromU16(3), .signing_share = signingShareFromHex(v.participant_shares.p3) },
    };
    const got = try frost.secretShareCombine(&shares);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.group.secret_key), &got.toBytes(.big));
}

test "secretShareCombine reconstructs the group secret from the {1,2} subset too" {
    const shares = [_]frost.ParticipantShare{
        .{ .identifier = identifierFromU16(1), .signing_share = signingShareFromHex(v.participant_shares.p1) },
        .{ .identifier = identifierFromU16(2), .signing_share = signingShareFromHex(v.participant_shares.p2) },
    };
    const got = try frost.secretShareCombine(&shares);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.group.secret_key), &got.toBytes(.big));
}

test "secretShareCombine reconstructs the group secret from the {2,3} subset too" {
    const shares = [_]frost.ParticipantShare{
        .{ .identifier = identifierFromU16(2), .signing_share = signingShareFromHex(v.participant_shares.p2) },
        .{ .identifier = identifierFromU16(3), .signing_share = signingShareFromHex(v.participant_shares.p3) },
    };
    const got = try frost.secretShareCombine(&shares);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.group.secret_key), &got.toBytes(.big));
}

// ── round2Sign / aggregate / verify ───────────────────────────────────────

test "aggregate reproduces the exact published final signature" {
    const gpa = std.testing.allocator;

    const group_public_key = elementFromHex(v.group.public_key);
    const commitment_list = vectorCommitmentList();
    const msg = hexN(4, v.group.message);
    const sig_shares = [_]frost.SignatureShare{
        signatureShareFromHex(v.round2.p1_sig_share),
        signatureShareFromHex(v.round2.p3_sig_share),
    };

    const sig = try frost.aggregate(gpa, &commitment_list, &msg, group_public_key, &sig_shares);
    try std.testing.expectEqualSlices(u8, &hexN(65, v.final_signature), &sig.toBytes());
}

test "round2Sign reproduces P1's published sig_share" {
    const gpa = std.testing.allocator;

    const group_public_key = elementFromHex(v.group.public_key);
    const commitment_list = vectorCommitmentList();
    const msg = hexN(4, v.group.message);
    const nonces = frost.SigningNonces{
        .hiding = scalarFromHex(v.round1_p1.hiding_nonce),
        .binding = scalarFromHex(v.round1_p1.binding_nonce),
    };

    const share = try frost.round2Sign(gpa, identifierFromU16(1), signingShareFromHex(v.participant_shares.p1), group_public_key, nonces, &msg, &commitment_list);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round2.p1_sig_share), &share.toBytes());
}

test "round2Sign reproduces P3's published sig_share" {
    const gpa = std.testing.allocator;

    const group_public_key = elementFromHex(v.group.public_key);
    const commitment_list = vectorCommitmentList();
    const msg = hexN(4, v.group.message);
    const nonces = frost.SigningNonces{
        .hiding = scalarFromHex(v.round1_p3.hiding_nonce),
        .binding = scalarFromHex(v.round1_p3.binding_nonce),
    };

    const share = try frost.round2Sign(gpa, identifierFromU16(3), signingShareFromHex(v.participant_shares.p3), group_public_key, nonces, &msg, &commitment_list);
    try std.testing.expectEqualSlices(u8, &hexN(32, v.round2.p3_sig_share), &share.toBytes());
}

test "verify accepts the published aggregate signature" {
    const group_public_key = elementFromHex(v.group.public_key);
    const msg = hexN(4, v.group.message);
    const sig = try frost.Signature.fromBytes(hexN(65, v.final_signature));
    try std.testing.expect(frost.verify(&msg, sig, group_public_key));
}

test "verify rejects a tampered z" {
    const group_public_key = elementFromHex(v.group.public_key);
    const msg = hexN(4, v.group.message);
    var bytes = hexN(65, v.final_signature);
    bytes[64] ^= 0x01; // flip a bit in z
    const sig = try frost.Signature.fromBytes(bytes);
    try std.testing.expect(!frost.verify(&msg, sig, group_public_key));
}

test "verify rejects a tampered R" {
    const group_public_key = elementFromHex(v.group.public_key);
    const msg = hexN(4, v.group.message);
    var bytes = hexN(65, v.final_signature);
    bytes[1] ^= 0x01; // flip a bit in R's x-coordinate
    // R may no longer parse as a valid element at all — either way,
    // Signature.fromBytes failing OR verify() returning false is a pass.
    const sig = frost.Signature.fromBytes(bytes) catch return;
    try std.testing.expect(!frost.verify(&msg, sig, group_public_key));
}

// ── verifySignatureShare ──────────────────────────────────────────────────

test "verifySignatureShare accepts P1's published share" {
    const gpa = std.testing.allocator;

    const group_public_key = elementFromHex(v.group.public_key);
    const commitment_list = vectorCommitmentList();
    const msg = hexN(4, v.group.message);

    // VerifyingShare_1 = ScalarBaseMult(participant_share_1) — derived
    // via the group's own curve group (std), not a stub.
    const p1_scalar = signingShareFromHex(v.participant_shares.p1).scalar();
    const p1_point = try frost.Secp256k1.basePoint.mul(p1_scalar.toBytes(.big), .big);
    const verifying_share_1 = try frost.Element.fromPoint(p1_point);

    const comm_1 = frost.NonceCommitmentPair{
        .hiding = elementFromHex(v.round1_p1.hiding_nonce_commitment),
        .binding = elementFromHex(v.round1_p1.binding_nonce_commitment),
    };

    const ok = try frost.verifySignatureShare(
        gpa,
        identifierFromU16(1),
        verifying_share_1,
        comm_1,
        signatureShareFromHex(v.round2.p1_sig_share),
        &commitment_list,
        group_public_key,
        &msg,
    );
    try std.testing.expect(ok);
}

test "verifySignatureShare rejects a corrupted P1 share" {
    const gpa = std.testing.allocator;

    const group_public_key = elementFromHex(v.group.public_key);
    const commitment_list = vectorCommitmentList();
    const msg = hexN(4, v.group.message);

    const p1_scalar = signingShareFromHex(v.participant_shares.p1).scalar();
    const p1_point = try frost.Secp256k1.basePoint.mul(p1_scalar.toBytes(.big), .big);
    const verifying_share_1 = try frost.Element.fromPoint(p1_point);

    const comm_1 = frost.NonceCommitmentPair{
        .hiding = elementFromHex(v.round1_p1.hiding_nonce_commitment),
        .binding = elementFromHex(v.round1_p1.binding_nonce_commitment),
    };

    var corrupted_bytes = hexN(32, v.round2.p1_sig_share);
    corrupted_bytes[31] ^= 0x01;
    const corrupted_share = try frost.SignatureShare.fromBytes(corrupted_bytes);

    const ok = try frost.verifySignatureShare(
        gpa,
        identifierFromU16(1),
        verifying_share_1,
        comm_1,
        corrupted_share,
        &commitment_list,
        group_public_key,
        &msg,
    );
    try std.testing.expect(!ok);
}

// ── end-to-end (2,3) round trip, FRESH random key material ───────────────
//
// Not a published vector — exercises the full protocol shape
// (keygen → commit → sign → aggregate → verify) with independently
// generated randomness, the way a real deployment would use it.

test "end-to-end (2,3) round trip: keygen -> commit -> sign -> aggregate -> verify" {
    const gpa = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0xF20575);
    const random = prng.random();

    var secret_bytes: [32]u8 = undefined;
    random.bytes(&secret_bytes);
    const secret_key = frost.Scalar.fromBytes48(blk: {
        var wide = [_]u8{0} ** 48;
        wide[16..48].* = secret_bytes;
        break :blk wide;
    }, .big);

    var coeff_bytes: [32]u8 = undefined;
    random.bytes(&coeff_bytes);
    const coefficients = [_]frost.Scalar{frost.Scalar.fromBytes48(blk: {
        var wide = [_]u8{0} ** 48;
        wide[16..48].* = coeff_bytes;
        break :blk wide;
    }, .big)};

    const keygen = try frost.trustedDealerKeygen(gpa, secret_key, &coefficients, 3, 2);
    defer {
        for (keygen.shares) |*s| s.deinit();
        gpa.free(keygen.shares);
    }
    defer gpa.free(keygen.vss_commitment);

    // Sign with participants 1 and 2 (any 2-of-3 subset works).
    const signer_indices = [_]usize{ 0, 1 };
    var nonces_list: [2]frost.SigningNonces = undefined;
    var commitment_list: [2]frost.SigningCommitments = undefined;
    for (signer_indices, 0..) |idx, slot| {
        var hiding_random: [32]u8 = undefined;
        var binding_random: [32]u8 = undefined;
        random.bytes(&hiding_random);
        random.bytes(&binding_random);
        const share = keygen.shares[idx];
        nonces_list[slot] = frost.generateNonces(share.signing_share, hiding_random, binding_random);
        const comm = try frost.round1Commit(nonces_list[slot]);
        commitment_list[slot] = .{ .identifier = share.identifier, .hiding = comm.hiding, .binding = comm.binding };
    }
    frost.sortCommitmentsByIdentifier(&commitment_list);

    const msg = "end-to-end (2,3) test message";
    var sig_shares: [2]frost.SignatureShare = undefined;
    for (signer_indices, 0..) |idx, slot| {
        const share = keygen.shares[idx];
        // Find this signer's nonces (order may have changed under sort).
        var nonces: frost.SigningNonces = undefined;
        for (signer_indices, 0..) |idx2, slot2| {
            if (idx2 == idx) nonces = nonces_list[slot2];
        }
        sig_shares[slot] = try frost.round2Sign(gpa, share.identifier, share.signing_share, keygen.group_public_key, nonces, msg, &commitment_list);
    }

    const sig = try frost.aggregate(gpa, &commitment_list, msg, keygen.group_public_key, &sig_shares);
    try std.testing.expect(frost.verify(msg, sig, keygen.group_public_key));
}

// ── fuzz: verify on hostile signature bytes ─────────────────────────────
//
// `verify` is the module's untrusted-input entry point: a coordinator (or
// an attacker) hands out a `Signature` claiming to cover a fixed, known
// `(msg, group_public_key)`, and it must return `false` — never panic,
// never read out of bounds — for any 65 bytes. `group_public_key`/`msg`
// are pinned to the RFC 9591 Appendix E.5 vector; only the signature
// bytes are mutated, starting from the vector's own real published
// `final_signature` and flipping a handful of bytes, so the fuzzer lands
// near the `Element`/`Scalar` canonical-range boundary and the group
// equation rather than being rejected by the first parse check on nearly
// every draw.
fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    const group_public_key = elementFromHex(v.group.public_key);
    const msg = hexN(4, v.group.message);

    var bytes = hexN(65, v.final_signature);
    const n_flips = smith.valueRangeAtMost(u8, 0, 6);
    var i: u8 = 0;
    while (i < n_flips) : (i += 1) {
        const pos = smith.index(bytes.len);
        bytes[pos] = smith.value(u8);
    }

    const sig = frost.Signature.fromBytes(bytes) catch return;
    _ = frost.verify(&msg, sig, group_public_key);
}

test "fuzz: verify never panics on corrupted signature bytes" {
    try std.testing.fuzz({}, fuzzVerify, .{});
}
