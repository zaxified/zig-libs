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
        const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, v, gamma);
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
        bulletproofs.prove(std.testing.allocator, gens, &t, 256, scalarvec.zero),
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
    const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, v, gamma);
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

// ── 3(c). Soundness: proof for V does not verify against a different V' ───

test "soundness: a proof for V is rejected against a different commitment V'" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const n: usize = 8;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);

    const gamma1 = [_]u8{5} ++ [_]u8{0} ** 31;
    var prove_t = Transcript.init(bulletproofs.rangeproof_domain);
    const proof = try bulletproofs.prove(std.testing.allocator, gens, &prove_t, 50, gamma1);
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
    const proof = try bulletproofs.prove(std.testing.allocator, gens8, &prove_t, 50, gamma);
    defer proof.deinit(std.testing.allocator);

    // Verifying the n=8 proof against the n=16 generator set must not
    // spuriously accept.
    var vt = Transcript.init(bulletproofs.rangeproof_domain);
    try std.testing.expect(!bulletproofs.verify(gens16, &vt, commitment, proof));
}

// ── 4. Codec round-trips are covered directly in ipa.zig/rangeproof.zig's
//      own test blocks (REAL, ungated) — not duplicated here.
