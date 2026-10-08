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

/// Test-side value-style views of the pointer / out-param API: the tests below
/// are written against the vector's values, the module wants pointers.
const api = struct {
    const sl = spake2plus.scalar_length;
    const sh = spake2plus.share_length;
    const hl = spake2plus.hash_length;

    fn computeL(w1: [sl]u8) spake2plus.ComputeLError![sh]u8 {
        return spake2plus.computeL(&w1);
    }
    fn proverStart(x: [sl]u8, w0: [sl]u8) spake2plus.ProverStartError![sh]u8 {
        return spake2plus.proverStart(&x, &w0);
    }
    fn verifierStart(y: [sl]u8, w0: [sl]u8) spake2plus.VerifierStartError![sh]u8 {
        return spake2plus.verifierStart(&y, &w0);
    }
    fn deriveKeys(tt: []const u8) spake2plus.DerivedKeys {
        var out: spake2plus.DerivedKeys = undefined;
        spake2plus.deriveKeys(&out, tt);
        return out;
    }
    fn proverFinish(a: std.mem.Allocator, context: []const u8, id_p: []const u8, id_v: []const u8, w0: [sl]u8, w1: [sl]u8, x: [sl]u8, sp: [sh]u8, sv: [sh]u8, cv: [hl]u8) spake2plus.ProverFinishError!spake2plus.ProverFinishResult {
        var out: spake2plus.ProverFinishResult = undefined;
        try spake2plus.proverFinish(&out, a, context, id_p, id_v, &w0, &w1, &x, sp, sv, cv);
        return out;
    }
    fn verifierFinish(a: std.mem.Allocator, context: []const u8, id_p: []const u8, id_v: []const u8, w0: [sl]u8, l: [sh]u8, y: [sl]u8, sp: [sh]u8, sv: [sh]u8, cp: [hl]u8) spake2plus.VerifierFinishError!spake2plus.VerifierFinishResult {
        var out: spake2plus.VerifierFinishResult = undefined;
        try spake2plus.verifierFinish(&out, a, context, id_p, id_v, &w0, l, &y, sp, sv, cp);
        return out;
    }
    fn verifierConfirm(a: std.mem.Allocator, context: []const u8, id_p: []const u8, id_v: []const u8, w0: [sl]u8, l: [sh]u8, y: [sl]u8, sp: [sh]u8, sv: [sh]u8) spake2plus.VerifierConfirmError!spake2plus.VerifierConfirmResult {
        return spake2plus.verifierConfirm(a, context, id_p, id_v, &w0, l, &y, sp, sv);
    }
};

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
        &hexN(65, vec.z),
        &hexN(65, vec.v),
        &hexN(32, vec.w0),
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
    const l = try api.computeL(hexN(32, vec.w1));
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.l), &l);
}

test "KAT: proverStart reproduces the vector's published shareP" {
    const vec = v.vectors[0];
    const share_p = try api.proverStart(hexN(32, vec.x), hexN(32, vec.w0));
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.share_p), &share_p);
}

test "KAT: verifierStart reproduces the vector's published shareV" {
    const vec = v.vectors[0];
    const share_v = try api.verifierStart(hexN(32, vec.y), hexN(32, vec.w0));
    try std.testing.expectEqualSlices(u8, &hexN(65, vec.share_v), &share_v);
}

test "KAT: deriveKeys(vector's TT) reproduces K_main/K_confirmP/K_confirmV/K_shared byte-exact" {
    const vec = v.vectors[0];
    const keys = api.deriveKeys(&hexN(570, vec.tt));
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_main), &keys.k_main);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_p), &keys.k_confirm_p);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_confirm_v), &keys.k_confirm_v);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.k_shared), &keys.k_shared);
}

test "KAT: proverFinish reproduces Z, V, TT, key schedule, confirmP, and K_shared, all byte-exact" {
    const vec = v.vectors[0];
    const result = try api.proverFinish(
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

test "KAT: verifierConfirm reproduces confirmV byte-exact — with NO confirmP input" {
    const vec = v.vectors[0];
    const result = try api.verifierConfirm(
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

    // `confirmV = MAC(K_confirmV, shareP)` sits at the end of a chain that
    // runs Z -> V -> TT -> K_main -> K_confirmV, so this single byte-exact
    // assertion covers every one of them; `verifierFinish`'s own KAT below
    // pins the intermediates individually, on the same inputs, where
    // returning them is safe.
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_v), &result.confirm_v);
}

// Audit 2026-09-01. `VerifierConfirmResult` used to carry `tt` and `k_main`
// "for KAT visibility" while README/SPEC/its own doc comment all claimed the
// type made an unauthenticated `K_shared` impossible to obtain. It did not:
// either field yields the real `K_shared` in one public call, at the moment
// the Verifier has never seen `confirmP`. This pins the shape of the fix.
test "verifierConfirm returns confirmV and nothing that reconstructs K_shared" {
    const info = @typeInfo(spake2plus.VerifierConfirmResult).@"struct";
    try std.testing.expectEqual(@as(usize, 1), info.fields.len);
    try std.testing.expectEqualStrings("confirm_v", info.fields[0].name);
}

test "KAT: verifierFinish reproduces Z, V, TT, key schedule, confirmV, and K_shared, all byte-exact" {
    const vec = v.vectors[0];
    const result = try api.verifierFinish(
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

    try std.testing.expectError(error.InvalidShareV, api.proverFinish(
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

    try std.testing.expectError(error.InvalidShareP, api.verifierFinish(
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

    try std.testing.expectError(error.InvalidShareP, api.verifierFinish(
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

// Audit 2026-09-01: `verifierConfirm` arrived with commit `7386e724` as a
// THIRD entry point taking a share straight off the wire, and the §6 test
// set above was never extended to it. Both mutations — dropping either
// `rejectIdentity` inside `verifierConfirm` — survived the whole suite in
// Debug and ReleaseFast. The guards worked; nothing held them there.

test "verifierConfirm REJECTS an identity-element share_p (RFC 9383 §6 group-membership check)" {
    const vec = v.vectors[0];

    try std.testing.expectError(error.InvalidShareP, api.verifierConfirm(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        hexN(65, vec.l),
        hexN(32, vec.y),
        identity_share_v1,
        hexN(65, vec.share_v),
    ));
}

test "verifierConfirm REJECTS an identity-element registration record L (RFC 9383 §6 group-membership check)" {
    const vec = v.vectors[0];

    try std.testing.expectError(error.InvalidShareP, api.verifierConfirm(
        std.testing.allocator,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        hexN(32, vec.w0),
        identity_share_v1,
        hexN(32, vec.y),
        hexN(65, vec.share_p),
        hexN(65, vec.share_v),
    ));
}

// ── non-canonical scalars (the `rejectNonCanonical` guards) ─────────────
//
// Audit 2026-09-01: all twelve `rejectNonCanonical` call sites were
// unpinned — every one could be deleted with the suite green in both
// modes. They are not decorative. `p256`'s `mul` reduces the scalar mod
// `n` silently, measured: `basePoint.mul(n+1)` returns exactly
// `basePoint.mul(1)`. Without the guard a non-canonical encoding ALIASES
// onto a canonical one, so a registration record would have several valid
// `w1` pre-images and this module would diverge from BoringSSL and from
// every other implementation on malformed input, with nothing to notice.
//
// `n` itself is caught one step later (it multiplies to the identity), so
// `n+1` is the encoding that isolates the canonical check specifically.

/// The P-256 group order `n`, big-endian — RFC 9383's `p`.
const group_order_be: [32]u8 = .{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

/// `n + 1`. The low byte is 0x51, so incrementing it cannot carry.
const order_plus_one_be: [32]u8 = blk: {
    var s = group_order_be;
    s[31] += 1;
    break :blk s;
};

test "every entry point REJECTS a non-canonical scalar (>= the group order)" {
    const vec = v.vectors[0];
    const a = std.testing.allocator;
    const bad = order_plus_one_be;
    const w0 = hexN(32, vec.w0);
    const w1 = hexN(32, vec.w1);
    const l = hexN(65, vec.l);
    const share_p = hexN(65, vec.share_p);
    const share_v = hexN(65, vec.share_v);
    const cp = hexN(32, vec.confirm_p);
    const cv = hexN(32, vec.confirm_v);

    // computeL — the registration record, over the secret w1.
    try std.testing.expectError(error.InvalidScalar, api.computeL(bad));

    // proverStart / verifierStart — each of their two scalars.
    try std.testing.expectError(error.InvalidScalar, api.proverStart(bad, w0));
    try std.testing.expectError(error.InvalidScalar, api.proverStart(hexN(32, vec.x), bad));
    try std.testing.expectError(error.InvalidScalar, api.verifierStart(bad, w0));
    try std.testing.expectError(error.InvalidScalar, api.verifierStart(hexN(32, vec.y), bad));

    // proverFinish — all three of w0, w1, x.
    try std.testing.expectError(error.InvalidScalar, api.proverFinish(a, vec.context, vec.id_prover, vec.id_verifier, bad, w1, hexN(32, vec.x), share_p, share_v, cv));
    try std.testing.expectError(error.InvalidScalar, api.proverFinish(a, vec.context, vec.id_prover, vec.id_verifier, w0, bad, hexN(32, vec.x), share_p, share_v, cv));
    try std.testing.expectError(error.InvalidScalar, api.proverFinish(a, vec.context, vec.id_prover, vec.id_verifier, w0, w1, bad, share_p, share_v, cv));

    // verifierFinish / verifierConfirm — both of w0 and y, on each.
    try std.testing.expectError(error.InvalidScalar, api.verifierFinish(a, vec.context, vec.id_prover, vec.id_verifier, bad, l, hexN(32, vec.y), share_p, share_v, cp));
    try std.testing.expectError(error.InvalidScalar, api.verifierFinish(a, vec.context, vec.id_prover, vec.id_verifier, w0, l, bad, share_p, share_v, cp));
    try std.testing.expectError(error.InvalidScalar, api.verifierConfirm(a, vec.context, vec.id_prover, vec.id_verifier, bad, l, hexN(32, vec.y), share_p, share_v));
    try std.testing.expectError(error.InvalidScalar, api.verifierConfirm(a, vec.context, vec.id_prover, vec.id_verifier, w0, l, bad, share_p, share_v));
}

test "the non-canonical guard is load-bearing: n+1 would otherwise alias onto 1" {
    // Why the twelve assertions above matter, stated as a property of the
    // primitive rather than as a claim: the group operation itself does not
    // distinguish `n+1` from `1`, so the canonical check is the only thing
    // that does.
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    const l_one = try api.computeL(one);

    // Reduce `n+1` by hand to the value the primitive would have used, and
    // confirm it is `1` — i.e. the guard is rejecting a genuine alias, not
    // a value that would have failed anyway.
    try std.testing.expectEqual(@as(u8, 0x52), order_plus_one_be[31]);
    try std.testing.expectError(error.InvalidScalar, api.computeL(order_plus_one_be));
    try std.testing.expectEqual(@as(usize, 65), l_one.len);
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
    const l = try api.computeL(w1);

    // Round 1 — each party's first message needs nothing from the peer.
    const share_p = try api.proverStart(hexN(32, vec.x), w0);
    const share_v = try api.verifierStart(hexN(32, vec.y), w0);

    // Round 2a — the Verifier goes FIRST (RFC 9383 Appendix A.5): it
    // computes and transmits confirmV with no confirmP in existence yet.
    const verifier_confirm = try api.verifierConfirm(
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
    // Not foreknowledge: checking the OUTPUT against the published vector,
    // not supplying it as an input to make the call succeed.
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.confirm_v), &verifier_confirm.confirm_v);

    // Round 2b — the Prover receives confirmV (just produced above),
    // validates it, and only then computes its own confirmP + K_shared.
    const prover_result = try api.proverFinish(
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
    const verifier_result = try api.verifierFinish(
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

// Audit 2026-09-01: the suite ran the whole protocol only with both parties
// holding the SAME password. Every tamper test corrupted a MAC or a share
// after the fact, so the module's headline property — a WRONG PASSWORD does
// not authenticate — was asserted only indirectly, by the KAT numbers
// agreeing. This runs the real blind sequence with a Prover and a Verifier
// who disagree, and pins where it fails: at the FIRST confirmation, before
// either side has a key, and with the same typed error a tampered MAC gives
// (so a wrong password is not distinguishable from a corrupted message).
test "property: a mismatched password fails at the first confirmation, with no key on either side" {
    const vec = v.vectors[0];
    const a = std.testing.allocator;

    // The Verifier registered the real password; the Prover holds another.
    const w0 = hexN(32, vec.w0);
    const w1 = hexN(32, vec.w1);
    const l = try api.computeL(w1);

    var wrong_w0 = w0;
    wrong_w0[31] ^= 0x01;
    var wrong_w1 = w1;
    wrong_w1[31] ^= 0x01;

    const share_p = try api.proverStart(hexN(32, vec.x), wrong_w0);
    const share_v = try api.verifierStart(hexN(32, vec.y), w0);

    // The Verifier still emits a confirmV — it cannot yet know anything is
    // wrong, which is exactly why it must not treat this as authenticated.
    const verifier_confirm = try api.verifierConfirm(
        a,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        w0,
        l,
        hexN(32, vec.y),
        share_p,
        share_v,
    );

    // The Prover is the first party to learn: its recomputed confirmV does
    // not match, so it aborts WITHOUT emitting a confirmP and without a key.
    try std.testing.expectError(error.ConfirmationMismatch, api.proverFinish(
        a,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        wrong_w0,
        wrong_w1,
        hexN(32, vec.x),
        share_p,
        share_v,
        verifier_confirm.confirm_v,
    ));

    // And if a peer fabricates a confirmP anyway, the Verifier refuses it —
    // one guess consumed, no key handed back. (See SPEC.md's rate-limiting
    // obligation: this error is what a caller must count.)
    try std.testing.expectError(error.ConfirmationMismatch, api.verifierFinish(
        a,
        vec.context,
        vec.id_prover,
        vec.id_verifier,
        w0,
        l,
        hexN(32, vec.y),
        share_p,
        share_v,
        [_]u8{0xab} ** 32,
    ));
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

    try std.testing.expectError(error.ConfirmationMismatch, api.proverFinish(
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

    try std.testing.expectError(error.ConfirmationMismatch, api.verifierFinish(
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

    try std.testing.expectError(error.ConfirmationMismatch, api.proverFinish(
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

// Mutation run 2026-10-05: a `<` length check survived. RFC 9383 §3.2 (and
// BoringSSL's Register()) split exactly 80 octets into two 40-octet halves;
// anything longer is a caller error, not "use the first 80".
test "computeW0W1 takes exactly 80 octets: 79 and 81 are refused" {
    const buf = [_]u8{0x5a} ** 81;
    var out: spake2plus.W0W1 = undefined;
    try spake2plus.computeW0W1(&out, buf[0..80]);
    try std.testing.expectError(error.InvalidPbkdfOutputLength, spake2plus.computeW0W1(&out, buf[0..79]));
    // Refused input leaves nothing in `out`.
    try std.testing.expectEqual(@as(u8, 0), std.mem.max(u8, std.mem.asBytes(&out)));
    out = .{ .w0 = @splat(1), .w1 = @splat(1) };
    try std.testing.expectError(error.InvalidPbkdfOutputLength, spake2plus.computeW0W1(&out, buf[0..81]));
    try std.testing.expectEqual(@as(u8, 0), std.mem.max(u8, std.mem.asBytes(&out)));
}

/// Counts frees of memory that still held a non-zero octet. Only meaningful
/// in ReleaseFast: in the safe modes `Allocator.free` overwrites the slice
/// with 0xAA before the vtable sees it.
const WipeCheckAllocator = struct {
    child: std.mem.Allocator,
    frees: usize = 0,
    dirty_frees: usize = 0,

    fn allocator(self: *WipeCheckAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *WipeCheckAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *WipeCheckAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *WipeCheckAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *WipeCheckAllocator = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        if (!std.mem.allEqual(u8, m, 0)) self.dirty_frees += 1;
        self.child.rawFree(m, a, ra);
    }
};

// Review finding 2026-10-05 (during the mutation run): `verifierConfirm` and
// both `*Finish` on `ConfirmationMismatch` freed their own `TT` without
// zeroing it. `TT` ends in `w0` and is a one-call pre-image of `K_shared`,
// and `free` leaves memory intact in ReleaseFast. The caller never sees these
// buffers, so the module must wipe them (the SPEC's own "freeing it is not
// the same as zeroing it first").
test "transcripts the module frees itself are zeroed first (ReleaseFast)" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;
    const vec = v.vectors[0];
    var wc: WipeCheckAllocator = .{ .child = std.testing.allocator };
    const a = wc.allocator();
    var bad = hexN(32, vec.confirm_p);
    bad[0] ^= 1;

    _ = try api.verifierConfirm(a, vec.context, vec.id_prover, vec.id_verifier, hexN(32, vec.w0), hexN(65, vec.l), hexN(32, vec.y), hexN(65, vec.share_p), hexN(65, vec.share_v));
    try std.testing.expectError(error.ConfirmationMismatch, api.verifierFinish(a, vec.context, vec.id_prover, vec.id_verifier, hexN(32, vec.w0), hexN(65, vec.l), hexN(32, vec.y), hexN(65, vec.share_p), hexN(65, vec.share_v), bad));
    try std.testing.expectError(error.ConfirmationMismatch, api.proverFinish(a, vec.context, vec.id_prover, vec.id_verifier, hexN(32, vec.w0), hexN(32, vec.w1), hexN(32, vec.x), hexN(65, vec.share_p), hexN(65, vec.share_v), bad));

    try std.testing.expectEqual(@as(usize, 3), wc.frees);
    try std.testing.expectEqual(@as(usize, 0), wc.dirty_frees);
}

// The out-param contract (2026-10-08): a failed `*Finish` leaves nothing of the
// half-computed result in the caller's `out`, and `out.tt` is the empty slice
// (the module freed its own transcript).
test "proverFinish / verifierFinish zero `out` on every error" {
    const vec = v.vectors[0];
    const a = std.testing.allocator;
    var bad = hexN(32, vec.confirm_v);
    bad[0] ^= 1;
    const w0 = hexN(32, vec.w0);
    const w1 = hexN(32, vec.w1);
    const x = hexN(32, vec.x);
    const y = hexN(32, vec.y);

    var pf: spake2plus.ProverFinishResult = undefined;
    @memset(std.mem.asBytes(&pf), 0xee);
    try std.testing.expectError(error.ConfirmationMismatch, spake2plus.proverFinish(&pf, a, vec.context, vec.id_prover, vec.id_verifier, &w0, &w1, &x, hexN(65, vec.share_p), hexN(65, vec.share_v), bad));
    try std.testing.expectEqual(@as(usize, 0), pf.tt.len);
    inline for (.{ "confirm_p", "k_shared", "z", "v", "k_main", "k_confirm_p", "k_confirm_v" }) |f| {
        try std.testing.expect(std.mem.allEqual(u8, &@field(pf, f), 0));
    }

    var vf: spake2plus.VerifierFinishResult = undefined;
    @memset(std.mem.asBytes(&vf), 0xee);
    try std.testing.expectError(error.ConfirmationMismatch, spake2plus.verifierFinish(&vf, a, vec.context, vec.id_prover, vec.id_verifier, &w0, hexN(65, vec.l), &y, hexN(65, vec.share_p), hexN(65, vec.share_v), bad));
    try std.testing.expectEqual(@as(usize, 0), vf.tt.len);
    inline for (.{ "confirm_v", "k_shared", "z", "v", "k_main", "k_confirm_p", "k_confirm_v" }) |f| {
        try std.testing.expect(std.mem.allEqual(u8, &@field(vf, f), 0));
    }

    // An early (non-allocating) error, too.
    @memset(std.mem.asBytes(&pf), 0xee);
    try std.testing.expectError(error.InvalidShareV, spake2plus.proverFinish(&pf, a, vec.context, vec.id_prover, vec.id_verifier, &w0, &w1, &x, hexN(65, vec.share_p), identity_share_v1, bad));
    try std.testing.expectEqual(@as(usize, 0), pf.tt.len);
}
