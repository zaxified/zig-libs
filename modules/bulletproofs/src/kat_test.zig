// SPDX-License-Identifier: MIT

//! kat_test — the Bulletproofs property/soundness KAT harness.
//!
//! **No byte-exact third-party vector is possible here** (see
//! `transcript.zig`'s module doc comment: this module's Fiat-Shamir
//! transcript is self-contained and NOT dalek/Merlin-compatible, so a
//! proof this module produces cannot be checked against any published
//! Bulletproofs test vector, which are all tied to a specific
//! implementation's transcript). Verification is therefore
//! PROPERTY-based (completeness: an honest prover's proof verifies) and
//! SOUNDNESS-based (a cheating prover's proof — out-of-range value,
//! tampered proof field, wrong commitment, mismatched parameters — does
//! NOT verify), per CONVENTIONS.md §7's "pure logic" tier (property +
//! round-trip, no external oracle available).
//!
//! Every test that calls `prove`/`verify`/`proveIpa`/`verifyIpa` — i.e.
//! that would hit one of `ipa.zig`/`rangeproof.zig`'s `@panic
//! ("TODO(fable/core): ...")` stubs — is GATED behind
//! `gate.core_implemented` and reports **SKIP** (`error.SkipZigTest`)
//! while it is `false`. Tests that only exercise REAL code
//! (`Generators`, `Transcript`, `scalarvec`, the two structs' byte
//! codecs, `commit`, `deltaYZ`, and `rangeproof.prove`'s
//! `error.ValueOutOfRange` construction-time guard) are UNGATED and
//! PASS today — see each file's own test block for those (this file adds
//! only the cross-cutting/end-to-end scenarios that need more than one
//! module's pieces wired together).

const std = @import("std");
const builtin = @import("builtin");
const bulletproofs = @import("root.zig");
const gate = bulletproofs.gate;
const Generators = bulletproofs.Generators;
const Transcript = bulletproofs.Transcript;
const Ristretto255 = bulletproofs.Ristretto255;
const scalarvec = bulletproofs.scalarvec;

// ── 1. Completeness: honest prover, several in-range values (GATED) ───────

test "completeness: prove/verify accepts several in-range values, n=8" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);

    const values = [_]u64{ 0, 1, 42, 100, 254, 255 }; // 255 = 2^8 - 1, the max in-range value
    for (values) |v| {
        const gamma = [_]u8{@truncate(v + 1)} ++ [_]u8{0} ** 31;
        const v_bytes = [_]u8{@truncate(v)} ++ [_]u8{0} ** 31;
        const commitment = bulletproofs.commit(gens, v_bytes, gamma);

        var prove_t = Transcript.init(bulletproofs.rangeproof_domain);
        const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, &v, gamma);
        defer proof.deinit(std.testing.allocator);

        var verify_t = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(bulletproofs.verify(gens, &verify_t, commitment, proof));
    }
}

// ── 2. IPA standalone completeness (GATED) ─────────────────────────────────

test "completeness: IPA standalone accepts an honestly-built P, n=8" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);

    var a: [n][32]u8 = undefined;
    var b: [n][32]u8 = undefined;
    for (&a, &b, 0..) |*ai, *bi, i| {
        ai.* = [_]u8{@truncate(i + 1)} ++ [_]u8{0} ** 31;
        bi.* = [_]u8{@truncate(2 * i + 1)} ++ [_]u8{0} ** 31;
    }
    const q = gens.g; // any fixed generator works for a standalone IPA test

    const ip = try scalarvec.innerProduct(&a, &b);
    const term_ab = try scalarvec.multiScalarMul(&a, gens.g_vec);
    const term_bh = try scalarvec.multiScalarMul(&b, gens.h_vec);
    const p = term_ab.add(term_bh).add(try q.mul(ip));

    var prove_t = Transcript.init(bulletproofs.ipa_domain);
    const proof = try bulletproofs.proveIpa(std.testing.allocator, &prove_t, gens.g_vec, gens.h_vec, q, &a, &b);
    defer proof.deinit(std.testing.allocator);

    var verify_t = Transcript.init(bulletproofs.ipa_domain);
    try std.testing.expect(bulletproofs.verifyIpa(&verify_t, gens.g_vec, gens.h_vec, q, p, proof));
}

// ── 3(a). Soundness: out-of-range value rejected AT CONSTRUCTION (UNGATED) ─
//
// This scenario needs no core: `prove`'s error.ValueOutOfRange guard runs
// before the stub body, so this specific soundness case is real and
// passes today — see rangeproof.zig's own test block for the direct
// version of this check; this one additionally confirms it end-to-end
// through the `root.zig` re-export surface.

test "soundness: prove rejects v >= 2^n through the public API, without panicking" {
    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);
    var t = Transcript.init(bulletproofs.rangeproof_domain);
    try std.testing.expectError(
        error.ValueOutOfRange,
        bulletproofs.prove(std.testing.allocator, gens, &t, &@as(u64, 256), scalarvec.zero),
    );
}

// ── 3(b). Soundness: tamper each proof field (GATED) ───────────────────────

test "soundness: tampering any proof field is rejected" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);
    const v: u64 = 200;
    const gamma = [_]u8{5} ++ [_]u8{0} ** 31;
    const v_bytes = [_]u8{@truncate(v)} ++ [_]u8{0} ** 31;
    const commitment = bulletproofs.commit(gens, v_bytes, gamma);

    var prove_t = Transcript.init(bulletproofs.rangeproof_domain);
    const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, &v, gamma);
    defer proof.deinit(std.testing.allocator);

    // Sanity: the untampered proof verifies.
    {
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(bulletproofs.verify(gens, &vt, commitment, proof));
    }

    const flip_point = struct {
        fn f(p: Ristretto255) Ristretto255 {
            return p.add(Ristretto255.basePoint);
        }
    }.f;
    const flip_scalar = struct {
        fn f(s: [32]u8) [32]u8 {
            var out = s;
            out[0] ^= 1;
            return out;
        }
    }.f;

    // Tamper A, S, T1, T2.
    {
        var tampered = proof;
        tampered.a = flip_point(proof.a);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.s = flip_point(proof.s);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.t1 = flip_point(proof.t1);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.t2 = flip_point(proof.t2);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    // Tamper tau_x, mu, t_hat.
    {
        var tampered = proof;
        tampered.tau_x = flip_scalar(proof.tau_x);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.mu = flip_scalar(proof.mu);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.t_hat = flip_scalar(proof.t_hat);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    // Tamper each IPA L_i, R_i, and the final a/b.
    for (0..proof.ipa.l_vec.len) |i| {
        var tampered = proof;
        var l_vec = try std.testing.allocator.dupe(Ristretto255, proof.ipa.l_vec);
        defer std.testing.allocator.free(l_vec);
        l_vec[i] = flip_point(l_vec[i]);
        tampered.ipa.l_vec = l_vec;
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    for (0..proof.ipa.r_vec.len) |i| {
        var tampered = proof;
        var r_vec = try std.testing.allocator.dupe(Ristretto255, proof.ipa.r_vec);
        defer std.testing.allocator.free(r_vec);
        r_vec[i] = flip_point(r_vec[i]);
        tampered.ipa.r_vec = r_vec;
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.ipa.a = flip_scalar(proof.ipa.a);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
    {
        var tampered = proof;
        tampered.ipa.b = flip_scalar(proof.ipa.b);
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(!bulletproofs.verify(gens, &vt, commitment, tampered));
    }
}

// ── 2b. Zero-knowledge: repeated proofs of the SAME witness are not
//        bit-identical (GATED) — audit finding B2 ────────────────────────
//
// Every test above and below this one only checks COMPLETENESS (an honest
// proof verifies) and TAMPER-rejection (changing a byte breaks verification)
// -- both hold even for a prover that always draws the SAME "random"
// blinding (or none at all). The audit's `recover.zig` demonstrated that a
// predictable-blinding prover (its `W23` mutation: `randomScalar()` returns
// a fixed constant) still passes every test in this file, 58/58, while
// leaking the full witness `(gamma, v)` to anyone who sees the proof: with
// `alpha`/`rho`/`s_L`/`s_R`/`tau1`/`tau2` all fixed, `A` is a deterministic
// function of `(a_L, a_R)` alone (both fixed by `v`), so a SECOND proof of
// the identical `(v, gamma)` reproduces `A` byte-for-byte. This test is the
// suite's only guard against that regression.
test "zero-knowledge: two proofs of the identical witness are not bit-identical" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);
    const v: u64 = 137;
    const gamma = [_]u8{42} ++ [_]u8{0} ** 31;

    var t1 = Transcript.init(bulletproofs.rangeproof_domain);
    const p1 = try bulletproofs.prove(std.testing.allocator, gens, &t1, &v, gamma);
    defer p1.deinit(std.testing.allocator);

    var t2 = Transcript.init(bulletproofs.rangeproof_domain);
    const p2 = try bulletproofs.prove(std.testing.allocator, gens, &t2, &v, gamma);
    defer p2.deinit(std.testing.allocator);

    // Both must independently verify (positive control: a broken runner
    // that always returns unequal would pass the checks below vacuously).
    {
        const commitment = bulletproofs.commit(gens, [_]u8{@truncate(v)} ++ [_]u8{0} ** 31, gamma);
        var vt1 = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(bulletproofs.verify(gens, &vt1, commitment, p1));
        var vt2 = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(bulletproofs.verify(gens, &vt2, commitment, p2));
    }

    // Every blinded commitment the proof carries must differ between the
    // two runs -- a fixed-blinding regression would make ALL of these
    // collide simultaneously (matching the audit's W23 recovery: A, S,
    // tau_x, and mu all become deterministic functions of (v, gamma)).
    try std.testing.expect(!p1.a.equivalent(p2.a));
    try std.testing.expect(!p1.s.equivalent(p2.s));
    try std.testing.expect(!p1.t1.equivalent(p2.t1));
    try std.testing.expect(!p1.t2.equivalent(p2.t2));
    try std.testing.expect(!std.mem.eql(u8, &p1.tau_x, &p2.tau_x));
    try std.testing.expect(!std.mem.eql(u8, &p1.mu, &p2.mu));
}

// ── 3(c). Soundness: proof for V does not verify against a different V' ───

test "soundness: a proof for V is rejected against a different commitment V'" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);

    const gamma1 = [_]u8{5} ++ [_]u8{0} ** 31;
    var prove_t = Transcript.init(bulletproofs.rangeproof_domain);
    const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, &@as(u64, 50), gamma1);
    defer proof.deinit(std.testing.allocator);

    const gamma2 = [_]u8{6} ++ [_]u8{0} ** 31;
    const other_commitment = bulletproofs.commit(gens, [_]u8{51} ++ [_]u8{0} ** 31, gamma2);

    var vt = Transcript.init(bulletproofs.rangeproof_domain);
    try std.testing.expect(!bulletproofs.verify(gens, &vt, other_commitment, proof));
}

// ── 3(d). Soundness: wrong n / generator mismatch is rejected ─────────────

test "soundness: verifying with a differently-sized Generators set is rejected" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const gens8 = try Generators.init(std.testing.allocator, 8);
    defer gens8.deinit(std.testing.allocator);
    const gens16 = try Generators.init(std.testing.allocator, 16);
    defer gens16.deinit(std.testing.allocator);

    const gamma = [_]u8{5} ++ [_]u8{0} ** 31;
    const v_bytes = [_]u8{50} ++ [_]u8{0} ** 31;
    const commitment = bulletproofs.commit(gens8, v_bytes, gamma);

    var prove_t = Transcript.init(bulletproofs.rangeproof_domain);
    const proof = try bulletproofs.prove(std.testing.allocator, gens8, &prove_t, &@as(u64, 50), gamma);
    defer proof.deinit(std.testing.allocator);

    // Verifying the n=8 proof against the n=16 generator set must not
    // spuriously accept.
    var vt = Transcript.init(bulletproofs.rangeproof_domain);
    try std.testing.expect(!bulletproofs.verify(gens16, &vt, commitment, proof));
}

// ── 3(e). Soundness: randomized forgery — discriminating power, not just
//         "some tampers are caught" (GATED) — audit finding B4 ───────────
//
// The hand-picked tampers in 3(b) each flip ONE bit of ONE field and all get
// caught -- but a verifier that only compares, say, the first byte of the
// final IPA equation's two sides would ALSO catch every one of those (a
// single-bit flip almost always changes byte 0 too) while accepting roughly
// 1 forged proof in 256. Audit finding B4, reproduced here structurally:
// `ipa.verifyIpa`'s final check weakened from `lhs.equivalent(rhs)` to
// comparing only the first encoded byte survives 3(b) entirely, 58/58, and
// is caught only by measuring the ACCEPTANCE RATE of many independent
// random forgeries rather than a fixed list of hand-picked ones.
test "soundness: random forgeries of L_0 are never accepted (discriminating power)" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);
    const v: u64 = 200;
    const gamma = [_]u8{5} ++ [_]u8{0} ** 31;
    const commitment = bulletproofs.commit(gens, [_]u8{@truncate(v)} ++ [_]u8{0} ** 31, gamma);

    var prove_t = Transcript.init(bulletproofs.rangeproof_domain);
    const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, &v, gamma);
    defer proof.deinit(std.testing.allocator);

    // Positive control: the untampered proof must verify, or the loop below
    // proves nothing (a runner that always rejects would also show 0/N).
    {
        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        try std.testing.expect(bulletproofs.verify(gens, &vt, commitment, proof));
    }

    var prng = std.Random.DefaultPrng.init(0xB4_2026_0910);
    const random = prng.random();
    // 500, not the audit's own 20,000 -- this lane runs in Debug (10-50x
    // slower per `verify` call than the audit's ReleaseFast measurement),
    // and 500 trials already makes a ~1-in-256 acceptance rate (the exact
    // rate a `W03`-style weakened comparison produces) fail with
    // overwhelming probability (P(0 hits in 500 draws at p=1/256) ~= 15%,
    // so a real regression at that rate is caught the large majority of
    // runs and, per this fix's own RED measurement, was caught outright).
    //
    // Measured 2026-09-17: 500 trials of `verify` (each a full bulletproof
    // verification, n=8) took ~46s isolated in Debug -- the module's own
    // full-gate Debug timeout contributor (`scripts/modtest bulletproofs`:
    // 1m55s whole module). Debug is a smoke lane, not the statistical gate:
    // ReleaseFast/ReleaseSafe/ReleaseSmall keep the full 500 (and `verify`
    // there is the 10-50x-faster path the math above was sized for anyway).
    // 80 trials still gives P(0 hits at p=1/256) ~= 73% -- a materially
    // weaker Debug smoke check, but the discriminating-power claim this test
    // makes is carried by the non-Debug lanes at full strength.
    const trials: usize = if (builtin.mode == .Debug) 80 else 500;
    var accepted: usize = 0;
    for (0..trials) |_| {
        var tampered = proof;
        var l_vec = try std.testing.allocator.dupe(Ristretto255, proof.ipa.l_vec);
        defer std.testing.allocator.free(l_vec);
        var wide: [64]u8 = undefined;
        random.bytes(&wide);
        const k = Ristretto255.scalar.reduce64(wide);
        l_vec[0] = Ristretto255.basePoint.mul(k) catch continue; // a fresh random point
        tampered.ipa.l_vec = l_vec;

        var vt = Transcript.init(bulletproofs.rangeproof_domain);
        if (bulletproofs.verify(gens, &vt, commitment, tampered)) accepted += 1;
    }
    // Measured 2026-09-10 against the real (unweakened) `equivalent` check:
    // 0 of 500 accepted. A verifier weakened to compare only the first
    // encoded byte of the final check (audit's `W03`) accepted 4 of 500 in
    // the same run (~1-in-256 rate, matches the weakening exactly) --
    // confirmed via a temporary mutation during this fix.
    try std.testing.expectEqual(@as(usize, 0), accepted);
}

// ── 4. Codec round-trips are covered directly in ipa.zig/rangeproof.zig's
//      own test blocks (REAL, ungated) — not duplicated here.
