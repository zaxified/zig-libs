// SPDX-License-Identifier: MIT
//! Tests for `chain.Options.revocation` (CRL checking inside `verifyChain`) over
//! the fixtures in `data/crl/`: the two-level RSA CA of `crl_test.zig` and the
//! three-level `chain_*` set made by `tools/gen_crl_chain_fixtures.py`, whose
//! verdicts were confirmed by `openssl verify -crl_check[_all]` when generated.

const std = @import("std");
const testing = std.testing;
const chain = @import("chain.zig");

fn fx(comptime name: []const u8) []const u8 {
    return @embedFile("data/crl/" ++ name);
}

/// Fixture time base (see `crl_test.zig`): CRLs issued at t0, nextUpdate t0 + 7 days.
const t0: i64 = 1_767_225_600;
const now: i64 = t0 + 3600;
const day: i64 = 86_400;

fn verify(
    chn: []const chain.CertDer,
    anchors: []const chain.CertDer,
    rev: ?chain.Revocation,
    now_sec: i64,
) chain.VerifyChainError!chain.VerifiedChain {
    return chain.verifyChain(testing.allocator, chn, anchors, .{ .now_sec = now_sec, .revocation = rev });
}

// ── two-level: RSA CA + leaf ────────────────────────────────────────────────

fn twoLevel(comptime leaf_name: []const u8, crls: []const []const u8, rev: chain.Revocation) chain.VerifyChainError!chain.VerifiedChain {
    var r = rev;
    r.crls = crls;
    return verify(&.{fx(leaf_name)}, &.{fx("rsa_ca.der")}, r, now);
}

test "leaf only: good passes; revoked and hold reject" {
    const crls: []const []const u8 = &.{fx("rsa.crl")};
    const v = try twoLevel("rsa_leaf_good.der", crls, .{ .crls = &.{} });
    try testing.expectEqual(@as(u32, 1), v.depth);
    try testing.expectError(error.CertificateRevoked, twoLevel("rsa_leaf_revoked.der", crls, .{ .crls = &.{} }));
    // certificateHold counts as revoked for the chain API.
    try testing.expectError(error.CertificateRevoked, twoLevel("rsa_leaf_hold.der", crls, .{ .crls = &.{} }));
}

test "revocation = null checks nothing, even for a revoked leaf" {
    _ = try verify(&.{fx("rsa_leaf_revoked.der")}, &.{fx("rsa_ca.der")}, null, now);
    // Also the default `Options`.
    _ = try chain.verifyChain(testing.allocator, &.{fx("rsa_leaf_revoked.der")}, &.{fx("rsa_ca.der")}, .{ .now_sec = now });
}

test "no CRL for the certificate: unknown = reject fails closed, allow passes" {
    for ([_][]const []const u8{ &.{}, &.{fx("chain_root_empty.crl")} }) |crls| {
        // No CRLs at all, and a CRL of some other issuer (skipped).
        try testing.expectError(error.RevocationStatusUnknown, twoLevel("rsa_leaf_good.der", crls, .{ .crls = &.{} }));
        _ = try twoLevel("rsa_leaf_good.der", crls, .{ .crls = &.{}, .unknown = .allow });
    }
    // `allow` only excuses a missing verdict, never a revocation.
    try testing.expectError(error.CertificateRevoked, twoLevel("rsa_leaf_revoked.der", &.{fx("rsa.crl")}, .{ .crls = &.{}, .unknown = .allow }));
}

test "expired or not-yet-valid CRL gives no verdict" {
    const c: chain.Revocation = .{ .crls = &.{fx("rsa.crl")} };
    // The certificates are valid until 2030; only the CRL window (t0 .. t0 + 7 d) moves.
    try testing.expectError(error.RevocationStatusUnknown, verify(&.{fx("rsa_leaf_good.der")}, &.{fx("rsa_ca.der")}, c, t0 + 7 * day));
    try testing.expectError(error.RevocationStatusUnknown, verify(&.{fx("rsa_leaf_good.der")}, &.{fx("rsa_ca.der")}, c, t0 - 1));
    var allow = c;
    allow.unknown = .allow;
    _ = try verify(&.{fx("rsa_leaf_revoked.der")}, &.{fx("rsa_ca.der")}, allow, t0 + 7 * day); // an expired CRL cannot revoke either
    // A CRL without nextUpdate needs max_age_sec.
    const nn: chain.Revocation = .{ .crls = &.{fx("rsa_no_next.crl")} };
    try testing.expectError(error.RevocationStatusUnknown, verify(&.{fx("rsa_leaf_good.der")}, &.{fx("rsa_ca.der")}, nn, now));
    var nn_age = nn;
    nn_age.max_age_sec = 2 * 3600;
    _ = try verify(&.{fx("rsa_leaf_good.der")}, &.{fx("rsa_ca.der")}, nn_age, now);
    try testing.expectError(error.CertificateRevoked, verify(&.{fx("rsa_leaf_revoked.der")}, &.{fx("rsa_ca.der")}, nn_age, now));
}

test "a CRL that refuses or is out of scope gives no verdict; another CRL still can" {
    // Delta CRL: refused, so no verdict.
    try testing.expectError(error.RevocationStatusUnknown, twoLevel("rsa_leaf_good.der", &.{fx("rsa_delta.crl")}, .{ .crls = &.{} }));
    // A partitioned CRL that names another distribution point than dp2's.
    try testing.expectError(error.RevocationStatusUnknown, twoLevel("rsa_leaf_dp2.der", &.{fx("rsa_idp1.crl")}, .{ .crls = &.{} }));
    // ... and the matching one revokes.
    try testing.expectError(error.CertificateRevoked, twoLevel("rsa_leaf_dp1.der", &.{fx("rsa_idp1.crl")}, .{ .crls = &.{} }));
    // Unusable CRLs in front do not hide a usable one; a revoked verdict wins over a good one.
    _ = try twoLevel("rsa_leaf_good.der", &.{ fx("rsa_delta.crl"), fx("rsa_impostor.crl"), fx("rsa_empty.crl") }, .{ .crls = &.{} });
    try testing.expectError(error.CertificateRevoked, twoLevel("rsa_leaf_revoked.der", &.{ fx("rsa_empty.crl"), fx("rsa.crl") }, .{ .crls = &.{} }));
    try testing.expectError(error.CertificateRevoked, twoLevel("rsa_leaf_revoked.der", &.{ fx("rsa.crl"), fx("rsa_empty.crl") }, .{ .crls = &.{} }));
}

// ── three-level: root -> intermediate -> leaf ───────────────────────────────

const root = fx("chain_root.der");
const int1 = fx("chain_int.der");
const int2 = fx("chain_int2.der");
const leaf = fx("chain_leaf.der");
const leaf_rev = fx("chain_leaf_revoked.der");
const root_ok = fx("chain_root_empty.crl");
const root_rev_int = fx("chain_root_revokes_int.crl");
const root_rev_both = fx("chain_root_revokes_both.crl");
const int_crl = fx("chain_int.crl");

test "three levels: every certificate of the path has a verdict" {
    const crls: []const []const u8 = &.{ root_ok, int_crl };
    const v = try verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls }, now);
    try testing.expectEqual(@as(u32, 2), v.depth);
    try testing.expectError(error.CertificateRevoked, verify(&.{ leaf_rev, int1 }, &.{root}, .{ .crls = crls }, now));
}

test "revoked intermediate: rejected under full_chain, not looked at under leaf_only" {
    const crls: []const []const u8 = &.{ root_rev_int, int_crl };
    try testing.expectError(error.CertificateRevoked, verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls }, now));
    _ = try verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls, .scope = .leaf_only }, now);
    // The other intermediate is not on the root's CRL.
    _ = try verify(&.{ leaf, int2 }, &.{root}, .{ .crls = crls }, now);
}

test "the intermediate has no verdict: full_chain needs the root's CRL, leaf_only does not" {
    const crls: []const []const u8 = &.{int_crl};
    try testing.expectError(error.RevocationStatusUnknown, verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls }, now));
    _ = try verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls, .unknown = .allow }, now);
    _ = try verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls, .scope = .leaf_only }, now);
    // The leaf itself still needs a verdict under leaf_only, and can be revoked.
    try testing.expectError(error.RevocationStatusUnknown, verify(&.{ leaf, int1 }, &.{root}, .{ .crls = &.{root_ok}, .scope = .leaf_only }, now));
    try testing.expectError(error.CertificateRevoked, verify(&.{ leaf_rev, int1 }, &.{root}, .{ .crls = crls, .scope = .leaf_only }, now));
}

test "trust anchors are never checked, even when the chain carries the anchor" {
    // The root has no CRL of its own (and could not be checked against itself).
    _ = try verify(&.{ leaf, int1, root }, &.{root}, .{ .crls = &.{ root_ok, int_crl } }, now);
}

// BACKTRACKING. `int1` and `int2` are two certificates of the same CA (same
// subject, same key, hence the same SKI the leaf's AKI names — the AKI/SKI
// filter in `findIssuerAndVerify` keeps both as candidates), with serials 0x10
// and 0x11; the root's CRL revokes 0x10 only. With both in the presented chain
// `verifyChain` tries `int1` first, fails on its revocation and backtracks to
// `int2`. With only the revoked one there is a single candidate and the
// specific error survives; with both revoked every candidate failed.
test "revoked intermediate: backtracks to a same-subject re-issue that is not revoked" {
    const crls: []const []const u8 = &.{ root_rev_int, int_crl };
    const v = try verify(&.{ leaf, int1, int2 }, &.{root}, .{ .crls = crls }, now);
    try testing.expectEqual(@as(u32, 2), v.depth);
    _ = try verify(&.{ leaf, int2, int1 }, &.{root}, .{ .crls = crls }, now);
    try testing.expectError(error.CertificateRevoked, verify(&.{ leaf, int1 }, &.{root}, .{ .crls = crls }, now));
    try testing.expectError(error.NoTrustedPath, verify(&.{ leaf, int1, int2 }, &.{root}, .{ .crls = &.{ root_rev_both, int_crl } }, now));
    // Without revocation checking the first candidate is simply accepted.
    _ = try verify(&.{ leaf, int1, int2 }, &.{root}, null, now);
}
