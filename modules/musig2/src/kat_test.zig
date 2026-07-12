// SPDX-License-Identifier: MIT
//! Tests against the official BIP327 test vectors (`kat_vectors.zig`).
//!
//! Coverage, by category:
//!
//!   - `keySort` and `nonceGen`: byte-exact against every official vector
//!     (`key_sort`, `nonce_gen`).
//!   - Every "valid" vector: byte-exact — `key_agg`'s 4 aggregate keys,
//!     `nonce_agg`'s 2 aggregate nonces (including the point-at-infinity
//!     encoding), `sign_verify`'s 6 partial signatures (each additionally
//!     re-checked through the top-level `partialSigVerify`), `tweak`'s 5
//!     tweaked partial signatures (each additionally re-checked through
//!     the tweak-aware `partialSigVerify`), and ALL 4 of `sig_agg`'s final
//!     signatures — untweaked and tweaked — (each additionally verified
//!     under plain `bip340.verify` against the possibly-tweaked aggregate
//!     key — the scheme's headline property).
//!   - Every official "invalid contribution"/failure vector: exercised
//!     against the real leaf codec (`PlainPublicKey.fromBytes` /
//!     `PubNonce.fromBytes` / `AggNonce.fromBytes` / `SecNonce.k1Scalar` /
//!     `PartialSignature.fromBytes` / `KeyAggContext.applyTweak`) AND —
//!     wherever the composite call's own blame ordering surfaces that same
//!     failure (see each test's comment) — the composite function itself
//!     (`keyAgg`, `nonceAgg`, `sign`, `partialSigVerify`,
//!     `partialSigAgg`), including both equation-level `verify_fail`
//!     rejections (wrong signature = the negation of a valid one, and
//!     wrong signer) and the tweak error cases (`t >= n` at both the
//!     `applyTweak` leaf and through `sign`; tweaked key at infinity).
//!   - Two end-to-end 3-signer protocol runs (not published vectors):
//!     untweaked, and with an x-only (Taproot-style) tweak — nonceGen →
//!     nonceAgg → sign → partialSigVerify → partialSigAgg →
//!     `bip340.verify` accepts the aggregate under the (tweaked) key.

const std = @import("std");
const musig2 = @import("root.zig");
const bip340 = @import("bip340");
const v = @import("kat_vectors.zig");

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = try std.fmt.hexToBytes(out, hex_str);
    return out;
}

/// Builds `PlainPublicKey`s directly from bytes (bypassing `fromBytes`'s
/// eager validation) so a list containing one deliberately-invalid entry
/// (an official error vector) can still be assembled for feeding to
/// `keyAgg`/`sign`/etc — those composite functions must do their OWN real
/// validation on a list built this way, exactly like an untrusted list
/// coming off the wire would be.
fn rawPubkeys(buf: []musig2.PlainPublicKey, hex_list: []const []const u8, indices: []const usize) []musig2.PlainPublicKey {
    for (indices, 0..) |idx, i| buf[i] = .{ .bytes = hexN(33, hex_list[idx]) };
    return buf[0..indices.len];
}

fn rawPubnonces(buf: []musig2.PubNonce, hex_list: []const []const u8, indices: []const usize) []musig2.PubNonce {
    for (indices, 0..) |idx, i| buf[i] = .{ .bytes = hexN(66, hex_list[idx]) };
    return buf[0..indices.len];
}

/// Assembles a `[]musig2.Tweak` from a vector's parallel
/// `tweak_indices`/`is_xonly` selections over its hex tweak list.
fn tweakList(buf: []musig2.Tweak, hex_list: []const []const u8, indices: []const usize, is_xonly: []const bool) []musig2.Tweak {
    for (indices, is_xonly, 0..) |idx, xo, i| buf[i] = .{ .tweak = hexN(32, hex_list[idx]), .is_xonly = xo };
    return buf[0..indices.len];
}

// ── key_agg ─────────────────────────────────────────────────────────────

test "KAT key_agg: error_test_cases — real cpoint parsing rejects the blamed signer (leaf AND composite)" {
    for (v.key_agg.error_test_cases) |case| {
        var buf: [8]musig2.PlainPublicKey = undefined;
        const pks = rawPubkeys(&buf, v.key_agg.pubkeys, case.key_indices);

        // Leaf: the specific blamed pubkey fails to parse.
        try std.testing.expectError(error.InvalidPublicKey, musig2.PlainPublicKey.fromBytes(pks[case.invalid_signer].bytes));
        try std.testing.expectEqual(@as(?usize, case.invalid_signer), musig2.findInvalidPubkey(pks));

        // Composite: `keyAgg`'s per-pubkey pre-validation reports this
        // same error before any aggregation arithmetic runs — the blamed
        // signer wins over any later failure.
        try std.testing.expectError(error.InvalidPublicKey, musig2.keyAgg(pks));
    }
}

test "KAT key_agg: valid_test_cases — aggregate x-only key is byte-exact" {
    for (v.key_agg.valid_test_cases) |case| {
        var buf: [8]musig2.PlainPublicKey = undefined;
        for (case.key_indices, 0..) |idx, i| {
            buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.key_agg.pubkeys[idx]));
        }
        const ctx = try musig2.keyAgg(buf[0..case.key_indices.len]);
        try std.testing.expectEqualSlices(u8, &hexN(32, case.expected), &ctx.getXonlyPubkey());
    }
}

test "KAT key_agg: tweak_error_test_cases — out-of-range tweak and infinite tweaked key are rejected" {
    // Case 0: t = n exactly (x-only) → TweakOutOfRange. Case 1: a plain
    // tweak crafted so g·Q + t·G is EXACTLY the point at infinity →
    // TweakedKeyIsInfinite (the fail-closed "tweak cancelled the key"
    // rejection).
    const expected_errors = [_]anyerror{ error.TweakOutOfRange, error.TweakedKeyIsInfinite };
    for (v.key_agg.tweak_error_test_cases, expected_errors) |case, expected| {
        var buf: [8]musig2.PlainPublicKey = undefined;
        for (case.key_indices, 0..) |idx, i| {
            buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.key_agg.pubkeys[idx]));
        }
        var ctx = try musig2.keyAgg(buf[0..case.key_indices.len]);
        var failed: ?anyerror = null;
        for (case.tweak_indices, case.is_xonly) |tweak_idx, is_xonly| {
            ctx = ctx.applyTweak(hexN(32, v.key_agg.tweaks[tweak_idx]), is_xonly) catch |err| {
                failed = err;
                break;
            };
        }
        try std.testing.expectEqual(@as(?anyerror, expected), failed);
    }
}

// ── key_sort — REAL, full pass ─────────────────────────────────────────────

test "KAT keySort: matches the official sorted_pubkeys byte-exactly" {
    var buf: [8]musig2.PlainPublicKey = undefined;
    for (v.key_sort.pubkeys, 0..) |hex, i| buf[i] = .{ .bytes = hexN(33, hex) };
    const pks = buf[0..v.key_sort.pubkeys.len];

    musig2.keySort(pks);

    for (pks, 0..) |pk, i| {
        try std.testing.expectEqualSlices(u8, &hexN(33, v.key_sort.sorted_pubkeys[i]), &pk.bytes);
    }
}

// ── nonce_gen — REAL, full pass ───────────────────────────────────────────

test "KAT nonceGen: byte-exact secnonce/pubnonce against all 4 official vectors" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    for (v.nonce_gen.test_cases) |case| {
        const sk: ?[32]u8 = if (case.sk) |s| hexN(32, s) else null;
        const pk = hexN(33, case.pk);
        const aggpk: ?[32]u8 = if (case.aggpk) |a| hexN(32, a) else null;

        const msg: ?[]u8 = if (case.msg) |m| try hexAlloc(gpa, m) else null;
        defer if (msg) |m| gpa.free(m);
        const extra_in: ?[]u8 = if (case.extra_in) |e| try hexAlloc(gpa, e) else null;
        defer if (extra_in) |e| gpa.free(e);

        const rand_prime = hexN(32, case.rand_);

        const result = try musig2.nonceGen(sk, pk, aggpk, msg, extra_in, rand_prime, io);

        try std.testing.expectEqualSlices(u8, &hexN(97, case.expected_secnonce), &result.secnonce.bytes);
        try std.testing.expectEqualSlices(u8, &hexN(66, case.expected_pubnonce), &result.pubnonce.bytes);
    }
}

// ── nonce_agg ───────────────────────────────────────────────────────────

test "KAT nonce_agg: error_test_cases — real cpoint parsing rejects the blamed signer (leaf AND composite)" {
    for (v.nonce_agg.error_test_cases) |case| {
        var buf: [8]musig2.PubNonce = undefined;
        const pns = rawPubnonces(&buf, v.nonce_agg.pnonces, case.pnonce_indices);

        try std.testing.expectError(error.InvalidPubNonce, musig2.PubNonce.fromBytes(pns[case.invalid_signer].bytes));
        try std.testing.expectEqual(@as(?usize, case.invalid_signer), musig2.findInvalidPubNonce(pns));

        // Composite: every case in this vector set has at least one
        // invalid pubnonce, caught by `nonceAgg`'s per-item validation
        // before any point summation.
        try std.testing.expectError(error.InvalidPubNonce, musig2.nonceAgg(pns));
    }
}

test "KAT nonce_agg: valid_test_cases — aggregate nonce is byte-exact (incl. the point-at-infinity encoding)" {
    for (v.nonce_agg.valid_test_cases) |case| {
        var buf: [8]musig2.PubNonce = undefined;
        for (case.pnonce_indices, 0..) |idx, i| {
            buf[i] = try musig2.PubNonce.fromBytes(hexN(66, v.nonce_agg.pnonces[idx]));
        }
        const agg = try musig2.nonceAgg(buf[0..case.pnonce_indices.len]);
        try std.testing.expectEqualSlices(u8, &hexN(66, case.expected), &agg.bytes);
    }
}

// ── sign_verify: sign_error_test_cases ─────────────────────────────────────
//
// Each sub-case below is annotated with WHERE its deliberately-broken
// ingredient is caught: `sign`'s check ordering (secnonce range → own-key
// match → session membership → per-pubkey validation inside
// `getSessionValues`) must report exactly the failure the vector blames —
// except the invalid-AGGNONCE cases, which the type system catches even
// earlier (an invalid aggnonce cannot construct an `AggNonce` at all).

test "KAT sign_verify: sign_error_test_cases (0) — signer's pubkey not in the session's pubkey list" {
    const case = v.sign_verify.sign_error_test_cases[0];
    const sk = try bip340.SecretKey.fromBytes(hexN(32, v.sign_verify.sk));

    var buf: [8]musig2.PlainPublicKey = undefined;
    const pks = rawPubkeys(&buf, v.sign_verify.pubkeys, case.key_indices);
    // Both pubkeys in this list ARE individually valid, and the aggnonce
    // IS valid too — but `sk`'s own derived pubkey is not among them, so
    // `sign`'s real "pubkey in session" check (step 3, before
    // `getSessionValues`/`keyAgg` are ever called) reports the error first.
    const secnonce = musig2.SecNonce.fromBytes(hexN(97, v.sign_verify.secnonces[case.secnonce_index]));
    const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, v.sign_verify.aggnonces[case.aggnonce_index]));
    const msg = hexN(32, v.sign_verify.msgs[case.msg_index]);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .msg = &msg };

    try std.testing.expectError(error.PubkeyNotInSession, musig2.sign(secnonce, sk, ctx));
}

test "KAT sign_verify: sign_error_test_cases (1) — signer 2 provided an invalid public key" {
    const case = v.sign_verify.sign_error_test_cases[1];
    const sk = try bip340.SecretKey.fromBytes(hexN(32, v.sign_verify.sk));

    var buf: [8]musig2.PlainPublicKey = undefined;
    const pks = rawPubkeys(&buf, v.sign_verify.pubkeys, case.key_indices);
    try std.testing.expectError(error.InvalidPublicKey, musig2.PlainPublicKey.fromBytes(pks[2].bytes));

    // Composite: the signer's own pubkey (key_indices[1] == pubkeys[0],
    // matching `sk`) IS in the list and the aggnonce IS valid, so `sign`
    // proceeds into `getSessionValues` -> `keyAgg`, whose per-pubkey
    // pre-validation finds pks[2] invalid.
    const secnonce = musig2.SecNonce.fromBytes(hexN(97, v.sign_verify.secnonces[case.secnonce_index]));
    const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, v.sign_verify.aggnonces[case.aggnonce_index]));
    const msg = hexN(32, v.sign_verify.msgs[case.msg_index]);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .msg = &msg };

    try std.testing.expectError(error.InvalidPublicKey, musig2.sign(secnonce, sk, ctx));
}

test "KAT sign_verify: sign_error_test_cases (2,3,4) — aggregate nonce is invalid" {
    // `AggNonce.fromBytes` is the check these vectors are actually about,
    // and — crucially — a `SessionContext` literally cannot be built with
    // an invalid `aggnonce` (the field's type is `AggNonce`, constructible
    // only via `fromBytes`), so the composite `sign()` is unreachable for
    // these by design; the leaf codec is the correct and only place to
    // exercise all three cases.
    for ([_]usize{ 2, 3, 4 }) |i| {
        const case = v.sign_verify.sign_error_test_cases[i];
        try std.testing.expectError(error.InvalidAggNonce, musig2.AggNonce.fromBytes(hexN(66, v.sign_verify.aggnonces[case.aggnonce_index])));
    }
}

test "KAT sign_verify: sign_error_test_cases (5) — secnonce is invalid (nonce reuse shape)" {
    const case = v.sign_verify.sign_error_test_cases[5];
    const sk = try bip340.SecretKey.fromBytes(hexN(32, v.sign_verify.sk));

    var buf: [8]musig2.PlainPublicKey = undefined;
    const pks = rawPubkeys(&buf, v.sign_verify.pubkeys, case.key_indices);
    const secnonce = musig2.SecNonce.fromBytes(hexN(97, v.sign_verify.secnonces[case.secnonce_index]));
    try std.testing.expectError(error.InvalidSecNonce, secnonce.k1Scalar());

    // Composite: safe — this secnonce's k1' is exactly zero, so `sign`'s
    // very first real check (step 1) reports it before anything else runs.
    const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, v.sign_verify.aggnonces[case.aggnonce_index]));
    const msg = hexN(32, v.sign_verify.msgs[case.msg_index]);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .msg = &msg };
    try std.testing.expectError(error.InvalidSecNonce, musig2.sign(secnonce, sk, ctx));
}

test "KAT sign_verify: valid_test_cases — partial signatures byte-exact; partialSigVerify accepts each" {
    const gpa = std.testing.allocator;
    const sk = try bip340.SecretKey.fromBytes(hexN(32, v.sign_verify.sk));

    for (v.sign_verify.valid_test_cases) |case| {
        var pk_buf: [8]musig2.PlainPublicKey = undefined;
        for (case.key_indices, 0..) |idx, i| pk_buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.sign_verify.pubkeys[idx]));
        const pks = pk_buf[0..case.key_indices.len];

        var pn_buf: [8]musig2.PubNonce = undefined;
        for (case.nonce_indices, 0..) |idx, i| pn_buf[i] = try musig2.PubNonce.fromBytes(hexN(66, v.sign_verify.pnonces[idx]));
        const pns = pn_buf[0..case.nonce_indices.len];

        // The vector's published aggnonce is exactly NonceAgg over the
        // case's pubnonce list (including the all-zero infinity encoding
        // of the "Both halves ... point at infinity" case).
        const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, v.sign_verify.aggnonces[case.aggnonce_index]));
        const computed_aggnonce = try musig2.nonceAgg(pns);
        try std.testing.expectEqualSlices(u8, &aggnonce.bytes, &computed_aggnonce.bytes);

        const msg = try hexAlloc(gpa, v.sign_verify.msgs[case.msg_index]);
        defer gpa.free(msg);
        const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .msg = msg };

        // The signing signer is always `sk`'s own (key_indices[signer_index]
        // == pubkeys[0]) and always uses secnonces[0] — the one whose
        // embedded pk is `sk`'s derived public key.
        const secnonce = musig2.SecNonce.fromBytes(hexN(97, v.sign_verify.secnonces[0]));
        const psig = try musig2.sign(secnonce, sk, ctx);
        try std.testing.expectEqualSlices(u8, &hexN(32, case.expected), &psig.bytes);

        // And the top-level PartialSigVerify accepts what sign produced.
        try musig2.partialSigVerify(psig, pns, pks, &.{}, msg, case.signer_index);
    }
}

test "KAT sign_verify: verify_fail_test_cases (2) — signature exceeds group size (real, s >= n)" {
    // Index 2's comment is "Signature exceeds group size": unlike indices
    // 0/1 (a genuinely canonical-but-wrong `s`, only catchable by the
    // verification equation), this one is caught right at
    // `PartialSignature.fromBytes`.
    const case = v.sign_verify.verify_fail_test_cases[2];
    try std.testing.expectError(error.InvalidPartialSignature, musig2.PartialSignature.fromBytes(hexN(32, case.sig)));
}

test "KAT sign_verify: verify_fail_test_cases (0,1) — wrong signature / wrong signer are rejected" {
    // "Wrong signature (negation of valid)" and "Wrong signer": both carry
    // a canonical (`s < n`) partial signature that is simply the wrong
    // value for the given signer/message — only the verification EQUATION
    // (and its parity/g' bookkeeping) can tell these apart from a genuine
    // one. Case 0 is the classic sign-flip: the negation of a valid
    // partial signature must NOT verify (a `g`/parity bug flips exactly
    // this case to "accept").
    const gpa = std.testing.allocator;
    for ([_]usize{ 0, 1 }) |i| {
        const case = v.sign_verify.verify_fail_test_cases[i];
        const psig = try musig2.PartialSignature.fromBytes(hexN(32, case.sig));
        var pk_buf: [8]musig2.PlainPublicKey = undefined;
        for (case.key_indices, 0..) |idx, j| pk_buf[j] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.sign_verify.pubkeys[idx]));
        var pn_buf: [8]musig2.PubNonce = undefined;
        for (case.nonce_indices, 0..) |idx, j| pn_buf[j] = try musig2.PubNonce.fromBytes(hexN(66, v.sign_verify.pnonces[idx]));

        const msg = try hexAlloc(gpa, v.sign_verify.msgs[case.msg_index]);
        defer gpa.free(msg);
        try std.testing.expectError(error.InvalidPartialSignature, musig2.partialSigVerify(
            psig,
            pn_buf[0..case.nonce_indices.len],
            pk_buf[0..case.key_indices.len],
            &.{},
            msg,
            case.signer_index,
        ));
    }
}

test "KAT sign_verify: verify_error_test_cases (0) — invalid pubnonce" {
    const case = v.sign_verify.verify_error_test_cases[0];
    const psig = try musig2.PartialSignature.fromBytes(hexN(32, case.sig));

    var pn_buf: [8]musig2.PubNonce = undefined;
    const pns = rawPubnonces(&pn_buf, v.sign_verify.pnonces, case.nonce_indices);
    var pk_buf: [8]musig2.PlainPublicKey = undefined;
    const pks = rawPubkeys(&pk_buf, v.sign_verify.pubkeys, case.key_indices);

    try std.testing.expectError(error.InvalidPubNonce, musig2.PubNonce.fromBytes(pns[case.signer_index].bytes));

    // Composite: every pubkey is individually valid, so
    // `partialSigVerify`'s signer-pubkey pre-check passes and
    // `nonceAgg(pubnonces)` (computed next, per BIP327's own algorithm)
    // finds the invalid pubnonce before ever reaching `keyAgg`.
    const msg = hexN(32, v.sign_verify.msgs[case.msg_index]);
    try std.testing.expectError(error.InvalidPubNonce, musig2.partialSigVerify(psig, pns, pks, &.{}, &msg, case.signer_index));
}

test "KAT sign_verify: verify_error_test_cases (1) — invalid pubkey" {
    const case = v.sign_verify.verify_error_test_cases[1];
    const psig = try musig2.PartialSignature.fromBytes(hexN(32, case.sig));

    var pk_buf: [8]musig2.PlainPublicKey = undefined;
    const pks = rawPubkeys(&pk_buf, v.sign_verify.pubkeys, case.key_indices);
    try std.testing.expectError(error.InvalidPublicKey, musig2.PlainPublicKey.fromBytes(pks[case.signer_index].bytes));

    // Composite: `partialSigVerify` validates the blamed signer's own
    // pubkey up front (before `nonceAgg` — this vector's pubnonces are
    // all individually valid), so the composite reports exactly the
    // failure the vector blames.
    var pn_buf: [8]musig2.PubNonce = undefined;
    const pns = rawPubnonces(&pn_buf, v.sign_verify.pnonces, case.nonce_indices);
    const msg = hexN(32, v.sign_verify.msgs[case.msg_index]);
    try std.testing.expectError(error.InvalidPublicKey, musig2.partialSigVerify(psig, pns, pks, &.{}, &msg, case.signer_index));
}

// ── tweak (tweak_vectors.json) ───────────────────────────────────────────

test "KAT tweak: valid_test_cases — tweaked partial signatures byte-exact; tweak-aware partialSigVerify accepts" {
    // All 5 official cases: a single x-only tweak, a single plain tweak,
    // plain-then-x-only, and both 4-tweak orderings (including x-only
    // BEFORE plain — this module permits it, per the vector's own note) —
    // each pins the g/gacc/tacc composition through `sign`'s
    // `d = g·gacc·d'` for a different tweak-chain shape.
    const sk = try bip340.SecretKey.fromBytes(hexN(32, v.tweak.sk));
    for (v.tweak.valid_test_cases) |case| {
        var pk_buf: [8]musig2.PlainPublicKey = undefined;
        for (case.key_indices, 0..) |idx, i| pk_buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.tweak.pubkeys[idx]));
        const pks = pk_buf[0..case.key_indices.len];

        // The vector's published aggnonce is NonceAgg over its pubnonces.
        var pn_buf: [8]musig2.PubNonce = undefined;
        for (case.nonce_indices, 0..) |idx, i| pn_buf[i] = try musig2.PubNonce.fromBytes(hexN(66, v.tweak.pnonces[idx]));
        const pns = pn_buf[0..case.nonce_indices.len];
        const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, v.tweak.aggnonce));
        const computed_aggnonce = try musig2.nonceAgg(pns);
        try std.testing.expectEqualSlices(u8, &aggnonce.bytes, &computed_aggnonce.bytes);

        var tw_buf: [8]musig2.Tweak = undefined;
        const tweaks = tweakList(&tw_buf, v.tweak.tweaks, case.tweak_indices, case.is_xonly);

        const msg = hexN(32, v.tweak.msg);
        const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .tweaks = tweaks, .msg = &msg };

        const secnonce = musig2.SecNonce.fromBytes(hexN(97, v.tweak.secnonce));
        const psig = try musig2.sign(secnonce, sk, ctx);
        try std.testing.expectEqualSlices(u8, &hexN(32, case.expected), &psig.bytes);

        // The tweak-aware top-level PartialSigVerify accepts it (and its
        // internal `g' = g·gacc` must mirror sign's flip for EVERY chain).
        try musig2.partialSigVerify(psig, pns, pks, tweaks, &msg, case.signer_index);

        // Cross-check: the SAME partial signature must NOT verify with
        // the tweaks dropped (a verifier that ignores tweaks is broken).
        try std.testing.expectError(error.InvalidPartialSignature, musig2.partialSigVerify(psig, pns, pks, &.{}, &msg, case.signer_index));
    }
}

test "KAT tweak: error_test_cases — tweak >= n rejected (leaf applyTweak AND composite sign)" {
    const case = v.tweak.error_test_cases[0];
    const sk = try bip340.SecretKey.fromBytes(hexN(32, v.tweak.sk));

    var pk_buf: [8]musig2.PlainPublicKey = undefined;
    for (case.key_indices, 0..) |idx, i| pk_buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.tweak.pubkeys[idx]));
    const pks = pk_buf[0..case.key_indices.len];

    // Leaf: ApplyTweak itself rejects t = n ("The tweak must be less
    // than n.").
    const keyagg_ctx = try musig2.keyAgg(pks);
    try std.testing.expectError(error.TweakOutOfRange, keyagg_ctx.applyTweak(hexN(32, v.tweak.tweaks[case.tweak_indices[0]]), case.is_xonly[0]));

    // Composite: `sign` hits the same rejection through
    // `getSessionValues`'s tweak loop (all other inputs are valid, so the
    // tweak check is genuinely what fires).
    var tw_buf: [8]musig2.Tweak = undefined;
    const tweaks = tweakList(&tw_buf, v.tweak.tweaks, case.tweak_indices, case.is_xonly);
    const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, v.tweak.aggnonce));
    const msg = hexN(32, v.tweak.msg);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .tweaks = tweaks, .msg = &msg };
    const secnonce = musig2.SecNonce.fromBytes(hexN(97, v.tweak.secnonce));
    try std.testing.expectError(error.TweakOutOfRange, musig2.sign(secnonce, sk, ctx));
}

// ── sig_agg ─────────────────────────────────────────────────────────────

test "KAT sig_agg: error_test_cases — real s<n check rejects the blamed signer (leaf AND composite)" {
    const case = v.sig_agg.error_test_cases[0];

    try std.testing.expectError(error.InvalidPartialSignature, musig2.PartialSignature.fromBytes(hexN(32, v.sig_agg.psigs[case.psig_indices[case.invalid_psig_signer]])));

    var ps_buf: [8]musig2.PartialSignature = undefined;
    for (case.psig_indices, 0..) |idx, i| ps_buf[i] = .{ .bytes = hexN(32, v.sig_agg.psigs[idx]) };
    const psigs = ps_buf[0..case.psig_indices.len];

    // Composite: safe — `partialSigAgg`'s real per-psig loop (added
    // specifically because BIP327's own `PartialSigAgg` algorithm
    // performs this check itself, not a caller-side precondition) finds
    // the out-of-range `s_i` before ever calling `getSessionValues`. The
    // vector's tweaks are passed through faithfully — irrelevant to the
    // outcome, since the psig check fires first regardless.
    var pk_buf: [8]musig2.PlainPublicKey = undefined;
    const pks = rawPubkeys(&pk_buf, v.sig_agg.pubkeys, case.key_indices);
    var tw_buf: [8]musig2.Tweak = undefined;
    const tweaks = tweakList(&tw_buf, v.sig_agg.tweaks, case.tweak_indices, case.is_xonly);
    const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, case.aggnonce));
    const msg = hexN(32, v.sig_agg.msg);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .tweaks = tweaks, .msg = &msg };

    try std.testing.expectError(error.InvalidPartialSignature, musig2.partialSigAgg(psigs, ctx));
}

test "KAT sig_agg: valid_test_cases — all 4 cases (untweaked AND tweaked) byte-exact AND verify under plain bip340" {
    // Cases 0/1 are untweaked; cases 2/3 carry non-empty `tweak_indices`
    // (one plain tweak; a plain+x-only+x-only chain) — all four assert
    // for real now that `applyTweak` exists.
    for (v.sig_agg.valid_test_cases) |case| {
        var pk_buf: [8]musig2.PlainPublicKey = undefined;
        for (case.key_indices, 0..) |idx, i| pk_buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.sig_agg.pubkeys[idx]));
        const pks = pk_buf[0..case.key_indices.len];

        // The vector's aggnonce is NonceAgg over the case's pubnonces.
        var pn_buf: [8]musig2.PubNonce = undefined;
        for (case.nonce_indices, 0..) |idx, i| pn_buf[i] = try musig2.PubNonce.fromBytes(hexN(66, v.sig_agg.pnonces[idx]));
        const aggnonce = try musig2.AggNonce.fromBytes(hexN(66, case.aggnonce));
        const computed_aggnonce = try musig2.nonceAgg(pn_buf[0..case.nonce_indices.len]);
        try std.testing.expectEqualSlices(u8, &aggnonce.bytes, &computed_aggnonce.bytes);

        var ps_buf: [8]musig2.PartialSignature = undefined;
        for (case.psig_indices, 0..) |idx, i| ps_buf[i] = try musig2.PartialSignature.fromBytes(hexN(32, v.sig_agg.psigs[idx]));

        var tw_buf: [8]musig2.Tweak = undefined;
        const tweaks = tweakList(&tw_buf, v.sig_agg.tweaks, case.tweak_indices, case.is_xonly);

        const msg = hexN(32, v.sig_agg.msg);
        const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks, .tweaks = tweaks, .msg = &msg };
        const sig = try musig2.partialSigAgg(ps_buf[0..case.psig_indices.len], ctx);
        try std.testing.expectEqualSlices(u8, &hexN(64, case.expected), &sig);

        // The scheme's headline property: the aggregate is a plain BIP340
        // signature under the (tweaked) aggregate x-only key — a vanilla
        // `bip340.verify` accepts it with no MuSig2 (or tweak) knowledge.
        var keyagg_ctx = try musig2.keyAgg(pks);
        for (tweaks) |tw| keyagg_ctx = try keyagg_ctx.applyTweak(tw.tweak, tw.is_xonly);
        const aggpk = try bip340.XOnlyPublicKey.fromBytes(keyagg_ctx.getXonlyPubkey());
        try std.testing.expect(bip340.verify(aggpk, &msg, try bip340.Signature.fromBytes(sig)));
    }
}

// ── end-to-end (not a published vector: the full multi-signer protocol) ──

test "end-to-end: 3 signers, nonceGen→nonceAgg→sign→partialSigVerify→partialSigAgg→bip340.verify" {
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const msg = "MuSig2 end-to-end over zig-libs bip340";

    var sks: [3]bip340.SecretKey = undefined;
    var pks: [3]musig2.PlainPublicKey = undefined;
    var secnonces: [3]musig2.SecNonce = undefined;
    var pubnonces: [3]musig2.PubNonce = undefined;
    for (0..3) |i| {
        var sk_bytes = [_]u8{0x42} ** 32; // arbitrary fixed test keys, well in range
        sk_bytes[31] = @intCast(i + 1);
        sks[i] = try bip340.SecretKey.fromBytes(sk_bytes);
        const p = try Secp256k1.basePoint.mul(sk_bytes, .big);
        pks[i] = try musig2.PlainPublicKey.fromBytes(p.toCompressedSec1());

        var rand_prime = [_]u8{0xA7} ** 32; // per-signer distinct nonce randomness
        rand_prime[0] = @intCast(i);
        const ng = try musig2.nonceGen(sk_bytes, pks[i].bytes, null, msg, null, rand_prime, io);
        secnonces[i] = ng.secnonce;
        pubnonces[i] = ng.pubnonce;
    }

    const aggnonce = try musig2.nonceAgg(&pubnonces);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = &pks, .msg = msg };

    var psigs: [3]musig2.PartialSignature = undefined;
    for (0..3) |i| {
        psigs[i] = try musig2.sign(secnonces[i], sks[i], ctx);
        try musig2.partialSigVerify(psigs[i], &pubnonces, &pks, &.{}, msg, i);
    }
    // Cross-signer sanity: signer 0's partial signature must NOT verify
    // as signer 1's (the "Wrong signer" failure shape, on fresh data).
    try std.testing.expectError(error.InvalidPartialSignature, musig2.partialSigVerify(psigs[0], &pubnonces, &pks, &.{}, msg, 1));

    const sig = try musig2.partialSigAgg(&psigs, ctx);
    const keyagg_ctx = try musig2.keyAgg(&pks);
    const aggpk = try bip340.XOnlyPublicKey.fromBytes(keyagg_ctx.getXonlyPubkey());
    try std.testing.expect(bip340.verify(aggpk, msg, try bip340.Signature.fromBytes(sig)));
}

test "end-to-end: 3 signers with an x-only (Taproot-style) tweak — aggregate verifies under the TWEAKED key" {
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const msg = "MuSig2 tweaked end-to-end over zig-libs bip340";

    var sks: [3]bip340.SecretKey = undefined;
    var pks: [3]musig2.PlainPublicKey = undefined;
    var secnonces: [3]musig2.SecNonce = undefined;
    var pubnonces: [3]musig2.PubNonce = undefined;
    for (0..3) |i| {
        var sk_bytes = [_]u8{0x51} ** 32; // arbitrary fixed test keys, well in range
        sk_bytes[31] = @intCast(i + 1);
        sks[i] = try bip340.SecretKey.fromBytes(sk_bytes);
        const p = try Secp256k1.basePoint.mul(sk_bytes, .big);
        pks[i] = try musig2.PlainPublicKey.fromBytes(p.toCompressedSec1());

        var rand_prime = [_]u8{0xC3} ** 32; // per-signer distinct nonce randomness
        rand_prime[0] = @intCast(i);
        const ng = try musig2.nonceGen(sk_bytes, pks[i].bytes, null, msg, null, rand_prime, io);
        secnonces[i] = ng.secnonce;
        pubnonces[i] = ng.pubnonce;
    }

    // Taproot-shaped x-only tweak: t = taggedHash("TapTweak", xbytes(Q))
    // over the untweaked aggregate key (BIP341's key-path-only commitment
    // shape — a deterministic public value, canonical for this fixed
    // signer set).
    const base_ctx = try musig2.keyAgg(&pks);
    const tweaks = [_]musig2.Tweak{
        .{ .tweak = bip340.taggedHash("TapTweak", &base_ctx.getXonlyPubkey()), .is_xonly = true },
    };

    const aggnonce = try musig2.nonceAgg(&pubnonces);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = &pks, .tweaks = &tweaks, .msg = msg };

    var psigs: [3]musig2.PartialSignature = undefined;
    for (0..3) |i| {
        psigs[i] = try musig2.sign(secnonces[i], sks[i], ctx);
        try musig2.partialSigVerify(psigs[i], &pubnonces, &pks, &tweaks, msg, i);
    }

    const sig = try musig2.partialSigAgg(&psigs, ctx);

    // The aggregate verifies under the TWEAKED x-only key (the Taproot
    // output key), and does NOT verify under the untweaked aggregate —
    // proof the tweak genuinely entered the signature, not just the tests.
    const tweaked_ctx = try base_ctx.applyTweak(tweaks[0].tweak, tweaks[0].is_xonly);
    const tweaked_pk = try bip340.XOnlyPublicKey.fromBytes(tweaked_ctx.getXonlyPubkey());
    try std.testing.expect(bip340.verify(tweaked_pk, msg, try bip340.Signature.fromBytes(sig)));
    const untweaked_pk = try bip340.XOnlyPublicKey.fromBytes(base_ctx.getXonlyPubkey());
    try std.testing.expect(!bip340.verify(untweaked_pk, msg, try bip340.Signature.fromBytes(sig)));
}
