// SPDX-License-Identifier: MIT
//! Byte-exact and property tests against `kat_vectors.zig`'s official
//! RFC 9383 Appendix C P-256/SHA-256 vector.
//!
//! Two sections, kept separate for what each isolates:
//!
//!   1. **Transcript/MAC plumbing**: tests written against
//!      `computeTranscript`/`mac` in isolation — a concrete demonstration
//!      that the transcript field order / length-prefix width / point
//!      encoding are correct against the RFC's own published numbers,
//!      independent of the other six crypto cores.
//!   2. **Byte-exact KAT + property harness**: written against `root.
//!      zig`'s full public API (`computeW0W1` is the one function with
//!      no oracle here — see its own doc comment — every other function
//!      IS exercised). All seven crypto cores are implemented, so this
//!      section runs and passes for real (see `root.zig`'s module doc
//!      comment and `SPEC.md`).

const std = @import("std");
const spake2plus = @import("root.zig");
const v = @import("kat_vectors.zig");

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

// ── REAL TODAY: computeTranscript + mac need no crypto core ────────────

test "REAL TODAY: computeTranscript reproduces RFC 9383 Appendix C's published TT byte-exact" {
    const vec = v.vectors[0];
    const tt = try spake2plus.computeTranscript(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
        hexN(65, vec.z),
        hexN(65, vec.v),
        hexN(32, vec.w0),
    );
    defer std.testing.allocator.free(tt);

    try std.testing.expectEqual(@as(usize, 570), tt.len);
    try std.testing.expectEqualSlices(u8, &hexN(570, vec.tt), tt);
}

test "REAL TODAY: mac(K_confirmP, shareV) reproduces the vector's published confirmP" {
    const vec = v.vectors[0];
    const got = spake2plus.mac(&hexN(32, vec.k_confirm_p), &hexN(65, vec.share_v));
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_p), &got);
}

test "REAL TODAY: mac(K_confirmV, shareP) reproduces the vector's published confirmV" {
    const vec = v.vectors[0];
    const got = spake2plus.mac(&hexN(32, vec.k_confirm_v), &hexN(65, vec.share_p));
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_v), &got);
}

test "REAL TODAY: mPoint/nPoint agree with the module's own compressed RFC 9383 §4 constants" {
    // Cross-checks root.zig's own "meta.model_after / mPoint / nPoint"
    // tests from this file's perspective too: the uncompressed points
    // computeTranscript folds into TT must be M/N's re-encoding, not
    // some other pair of points.
    const m = spake2plus.mPoint();
    const n = spake2plus.nPoint();
    try std.testing.expectEqualSlices(u8, &spake2plus.m_compressed_sec1, &m.toCompressedSec1());
    try std.testing.expectEqualSlices(u8, &spake2plus.n_compressed_sec1, &n.toCompressedSec1());
}

// ── byte-exact KAT (panics on the crypto-core stubs until implemented) ──

test "KAT: computeL reproduces the vector's published L" {
    const vec = v.vectors[0];
    const l = try spake2plus.computeL(hexN(32, vec.w1));
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.l), &l);
}

test "KAT: proverStart reproduces the vector's published shareP" {
    const vec = v.vectors[0];
    const share_p = try spake2plus.proverStart(hexN(32, vec.x), hexN(32, vec.w0));
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.share_p), &share_p);
}

test "KAT: verifierStart reproduces the vector's published shareV" {
    const vec = v.vectors[0];
    const share_v = try spake2plus.verifierStart(hexN(32, vec.y), hexN(32, vec.w0));
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.share_v), &share_v);
}

test "KAT: deriveKeys(vector's TT) reproduces K_main/K_confirmP/K_confirmV/K_shared byte-exact" {
    const vec = v.vectors[0];
    const keys = spake2plus.deriveKeys(&hexN(570, vec.tt));
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_main), &keys.k_main);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_p), &keys.k_confirm_p);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_v), &keys.k_confirm_v);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_shared), &keys.k_shared);
}

test "KAT: proverFinish reproduces Z, V, TT, key schedule, confirmP, and K_shared, all byte-exact" {
    const vec = v.vectors[0];
    const result = try spake2plus.proverFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(32, vec.w1),
        hexN(32, vec.x),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
        hexN(32, vec.confirm_v),
    );
    defer std.testing.allocator.free(result.tt);

    try std.testing.expectEqualSlices(u8, &hexN(65, vec.z), &result.z);
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.v), &result.v);
    try std.testing.expectEqualSlices(u8, &hexN(570, vec.tt), result.tt);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_main), &result.k_main);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_p), &result.k_confirm_p);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_v), &result.k_confirm_v);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_p), &result.confirm_p);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_shared), &result.k_shared);
}

test "KAT: verifierConfirm reproduces Z, V, TT, key schedule, and confirmV, byte-exact — with NO confirmP input" {
    const vec = v.vectors[0];
    const result = try spake2plus.verifierConfirm(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(65, vec.l),
        hexN(32, vec.y),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
    );
    defer std.testing.allocator.free(result.tt);

    try std.testing.expectEqualSlices(u8, &hexN(65, vec.z), &result.z);
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.v), &result.v);
    try std.testing.expectEqualSlices(u8, &hexN(570, vec.tt), result.tt);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_main), &result.k_main);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_p), &result.k_confirm_p);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_v), &result.k_confirm_v);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_v), &result.confirm_v);
    // Note what is NOT here: no k_shared field exists on this result type
    // at all (see VerifierConfirmResult's doc comment) — this is checked
    // by the type system, not an assertion.
}

test "KAT: verifierFinish reproduces Z, V, TT, key schedule, confirmV, and K_shared, all byte-exact" {
    const vec = v.vectors[0];
    const result = try spake2plus.verifierFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(65, vec.l),
        hexN(32, vec.y),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
        hexN(32, vec.confirm_p),
    );
    defer std.testing.allocator.free(result.tt);

    try std.testing.expectEqualSlices(u8, &hexN(65, vec.z), &result.z);
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.v), &result.v);
    try std.testing.expectEqualSlices(u8, &hexN(570, vec.tt), result.tt);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_main), &result.k_main);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_p), &result.k_confirm_p);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_v), &result.k_confirm_v);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_v), &result.confirm_v);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_shared), &result.k_shared);
}

// ── RFC 9383 §6 mandatory group-membership check ("MUST abort... upon
// receiving any value V such that V*h = I") ─────────────────────────────
//
// None of the tests above ever feed a degenerate (identity-element) share
// or registration record into proverFinish/verifierFinish — every KAT and
// property test above uses the vector's genuine, non-identity points, so
// the `rejectIdentity()` guards inside proverFinish/verifierFinish (the
// actual §6 abort condition) had no test making them fail. The
// P256.fromSec1 fuzz test nearby only exercises the bare decode+reject
// primitive in isolation, not the guard as wired into this module's own
// public entry points.
//
// The P-256 identity element's affine coordinates are (x=0, y=1) — see
// `p256`'s `group.zig` `P256.identityElement` / `AffineCoordinates.
// identityElement` — so its uncompressed SEC1 encoding is the fixed byte
// pattern below (0x04 || 32 zero bytes || 31 zero bytes || 0x01), built
// directly rather than via an unexported `P256` type from this module.
const identity_share_v1: [65]u8 = [_]u8{0x04} ++ [_]u8{0} ** 32 ++ [_]u8{0} ** 31 ++ [_]u8{0x01};

test "proverFinish REJECTS an identity-element share_v (RFC 9383 §6 group-membership check)" {
    const vec = v.vectors[0];
    const identity_share = identity_share_v1;

    try std.testing.expectError(error.InvalidShareV, spake2plus.proverFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(32, vec.w1),
        hexN(32, vec.x),
        hexN(65, vec.share_p),
        identity_share,
        hexN(32, vec.confirm_v),
    ));
}

test "verifierFinish REJECTS an identity-element share_p (RFC 9383 §6 group-membership check)" {
    const vec = v.vectors[0];
    const identity_share = identity_share_v1;

    try std.testing.expectError(error.InvalidShareP, spake2plus.verifierFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(65, vec.l),
        hexN(32, vec.y),
        identity_share,
        hexN(65, vec.share_v),
        hexN(32, vec.confirm_p),
    ));
}

test "verifierFinish REJECTS an identity-element registration record L (RFC 9383 §6 group-membership check)" {
    const vec = v.vectors[0];
    const identity_l = identity_share_v1;

    try std.testing.expectError(error.InvalidShareP, spake2plus.verifierFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        identity_l,
        hexN(32, vec.y),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
        hexN(32, vec.confirm_p),
    ));
}

// ── the false-anchor fix: a GENUINELY BLIND two-party run ───────────────
//
// The property test below this one ("end-to-end Prover<->Verifier run")
// pre-dates `verifierConfirm` and has to fabricate the Verifier's first
// (`confirmP`-less) call using the VECTOR's own already-published
// `confirm_p` — see its own comments. That is exactly the false-anchor
// shape this module's audit flagged: the test only passes because the
// answer was known in advance, not because the code can produce it blind.
//
// This test drives the SAME two parties through the SAME real message
// order (`proverStart` -> `verifierStart` -> `verifierConfirm` ->
// `proverFinish` -> `verifierFinish`, RFC 9383 Appendix A.5) but NEVER
// reads `vec.confirm_p`/`vec.confirm_v` as an INPUT to any call — every
// confirmation value fed into a function is one this test's own prior
// call just produced. The only place `vec.confirm_v` appears is a
// post-hoc equality check on `verifierConfirm`'s OUTPUT, which is not
// foreknowledge — it is what makes this a byte-exact KAT rather than a
// bare property test.
test "false anchor fix: verifierConfirm lets a genuinely blind Verifier go first, no foreknowledge of either confirmation value" {
    const vec = v.vectors[0];
    const w0 = hexN(32, vec.w0);
    const w1 = hexN(32, vec.w1);
    const l = try spake2plus.computeL(w1);

    // Round 1 — each party's first message needs nothing from the peer.
    const share_p = try spake2plus.proverStart(hexN(32, vec.x), w0);
    const share_v = try spake2plus.verifierStart(hexN(32, vec.y), w0);

    // Round 2a — the Verifier goes FIRST (RFC 9383 Appendix A.5): it
    // computes and transmits confirmV with no confirmP in existence yet.
    const verifier_confirm = try spake2plus.verifierConfirm(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        w0,
        l,
        hexN(32, vec.y),
        share_p,
        share_v,
    );
    defer std.testing.allocator.free(verifier_confirm.tt);
    // Not foreknowledge: checking the OUTPUT against the published vector,
    // not supplying it as an input to make the call succeed.
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_v), &verifier_confirm.confirm_v);

    // Round 2b — the Prover receives confirmV (just produced above),
    // validates it, and only then computes its own confirmP + K_shared.
    const prover_result = try spake2plus.proverFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        w0,
        w1,
        hexN(32, vec.x),
        share_p,
        share_v,
        verifier_confirm.confirm_v,
    );
    defer std.testing.allocator.free(prover_result.tt);

    // Round 2c — the Verifier receives confirmP (just produced above),
    // validates it, and only then obtains K_shared.
    const verifier_result = try spake2plus.verifierFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        w0,
        l,
        hexN(32, vec.y),
        share_p,
        share_v,
        prover_result.confirm_p,
    );
    defer std.testing.allocator.free(verifier_result.tt);

    try std.testing.expectEqualSlices(u8, &prover_result.k_shared, &verifier_result.k_shared);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_shared), &prover_result.k_shared);
}

// ── property / round-trip / tamper-rejection harness ────────────────────

// (The end-to-end Prover<->Verifier property run now lives above, as
// "false anchor fix: verifierConfirm lets a genuinely blind Verifier go
// first..." — it used to require fabricating the Verifier's confirmV from
// the vector's own already-published confirmP; `verifierConfirm` removed
// that need, so the property test and the false-anchor-fix test would
// otherwise have been near-duplicates.)

test "property: proverFinish REJECTS a tampered received_confirm_v" {
    const vec = v.vectors[0];
    var tampered_confirm_v = hexN(32, vec.confirm_v);
    tampered_confirm_v[0] ^= 0x01;

    try std.testing.expectError(error.ConfirmationMismatch, spake2plus.proverFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(32, vec.w1),
        hexN(32, vec.x),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
        tampered_confirm_v,
    ));
}

test "property: verifierFinish REJECTS a tampered received_confirm_p" {
    const vec = v.vectors[0];
    var tampered_confirm_p = hexN(32, vec.confirm_p);
    tampered_confirm_p[0] ^= 0x01;

    try std.testing.expectError(error.ConfirmationMismatch, spake2plus.verifierFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(65, vec.l),
        hexN(32, vec.y),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
        tampered_confirm_p,
    ));
}

test "property: proverFinish REJECTS a shareV tampered to a different (but still valid) point" {
    const vec = v.vectors[0];
    // Swap in shareP as if it were shareV — a well-formed, on-curve,
    // non-identity point, but the WRONG one. This changes Z/V/TT/
    // K_confirmV downstream, so the vector's genuine (now-stale)
    // confirm_v can no longer match this call's freshly recomputed
    // expected_confirmV — caught by the SAME ConfirmationMismatch path
    // the two dedicated tamper tests above exercise directly, this time
    // via a corrupted share rather than a corrupted MAC.
    const wrong_share_v = hexN(65, vec.share_p);

    try std.testing.expectError(error.ConfirmationMismatch, spake2plus.proverFinish(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(32, vec.w1),
        hexN(32, vec.x),
        hexN(65, vec.share_p),
        wrong_share_v,
        hexN(32, vec.confirm_v),
    ));
}
