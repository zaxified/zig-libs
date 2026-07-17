// SPDX-License-Identifier: MIT

//! harness_test — the verification harness with teeth: the REAL positive
//! control (proven today, no gated code on its path) plus the GATED
//! end-to-end anchor and NIZK-soundness controls (SKIP until
//! `gate.fable_core_implemented` flips).
//!
//! ## Positive control (REAL — teeth before the core)
//!
//! `BrokenCoconut.aggregateNoLagrange` mechanically recombines partial PS
//! signatures with all-ones weights instead of the Lagrange coefficients.
//! Because it uses only the mechanical oracles (`psSignWithSecret`-style
//! share signing + `psVerifyPlain`), it runs with the four Fable cores
//! still stubbed — and it demonstrates that the PS pairing-verify equation
//! REJECTS a mis-aggregated credential while the correctly Lagrange-
//! weighted aggregation is ACCEPTED. This is the anti-self-consistency
//! backbone: it proves the harness can tell a wrong threshold aggregation
//! from a right one BEFORE `aggregateCredential` exists.
//!
//! ## End-to-end anchor + soundness (GATED — SKIP today)
//!
//! Once the core lands: threshold-issue (`signPartial` × t) → aggregate
//! (`aggregateCredential`) → re-randomise + selective-disclosure show
//! (`proveCredential`) → verify (`verifyCredential`) PASSES; a tampered
//! credential / wrong disclosed value / mutated NIZK challenge / forged
//! undisclosed attribute all FAIL. No external byte-exact vector exists
//! for these (randomised blinding + Fiat-Shamir; see SPEC's tier finding),
//! so the anchor is the internal end-to-end property + these rejection
//! controls.

const std = @import("std");
const bls = @import("bls12_381");
const gate = @import("gate.zig");
const params_mod = @import("params.zig");
const keys = @import("keys.zig");
const cred = @import("credential.zig");
const lagrange = @import("lagrange.zig");

const g1 = bls.g1;
const Fr = bls.Fr;
const Parameters = params_mod.Parameters;

/// Mechanically sign a partial PS signature under authority `share`'s
/// Shamir share of `(x, y_i)`, over common base `h` — the mechanical
/// stand-in for the (gated) `credential.signPartial`, used only by the
/// positive control.
fn partialSignMech(share: keys.SecretKeyShare, h: g1.Affine, attributes: []const Fr) cred.PartialCredential {
    const as_sk = keys.SecretKey{ .x = share.x, .ys = share.ys };
    const e = cred.signingExponent(as_sk, attributes);
    return .{ .index = share.index, .h = h, .s = g1.Jacobian.fromAffine(h).scalarMul(e).toAffine() };
}

const BrokenCoconut = struct {
    /// CORRECT Lagrange-in-exponent aggregation: `s = Σ [lⱼ] sⱼ`.
    fn aggregateLagrange(indices: []const u64, partials: []const cred.PartialCredential) !cred.Credential {
        var acc = g1.Jacobian.identity;
        for (partials) |p| {
            const l = try lagrange.coefficientAtZero(indices, p.index);
            acc = acc.add(g1.Jacobian.fromAffine(p.s).scalarMul(l));
        }
        return .{ .h = partials[0].h, .s = acc.toAffine() };
    }

    /// BROKEN aggregation: ignores the Lagrange coefficients (`lⱼ = 1`).
    fn aggregateNoLagrange(partials: []const cred.PartialCredential) cred.Credential {
        var acc = g1.Jacobian.identity;
        for (partials) |p| acc = acc.add(g1.Jacobian.fromAffine(p.s));
        return .{ .h = partials[0].h, .s = acc.toAffine() };
    }
};

test "POSITIVE CONTROL: psVerifyPlain accepts Lagrange aggregation, rejects Lagrange-ignoring aggregation" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 3);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0xF00D);
    const kk = try keys.keygen(allocator, prng.random(), 3, 2, 4); // t=2, n=4
    defer kk.deinit(allocator);

    const attrs = [_]Fr{ frOf(5), frOf(6), frOf(7) };
    const h = p.commonBase(&attrs);

    // Two authorities (indices 1,3) produce partials over the common base.
    const partials = [_]cred.PartialCredential{
        partialSignMech(kk.sk_shares[0], h, &attrs),
        partialSignMech(kk.sk_shares[2], h, &attrs),
    };
    const indices = [_]u64{ partials[0].index, partials[1].index };

    // Correct Lagrange aggregation verifies under the group vk...
    const good = try BrokenCoconut.aggregateLagrange(&indices, &partials);
    try std.testing.expect(cred.psVerifyPlain(kk.master_vk, good, &attrs));
    // ...and byte-matches the single-signer oracle (Lagrange reconstructs x+Σmᵢyᵢ).
    const oracle = cred.psSignWithSecret(kk.master_sk, h, &attrs);
    try std.testing.expect(g1Eql(good.s, oracle.s));

    // The Lagrange-ignoring aggregation is CAUGHT by the pairing check.
    const bad = BrokenCoconut.aggregateNoLagrange(&partials);
    try std.testing.expect(!cred.psVerifyPlain(kk.master_vk, bad, &attrs));
}

test "POSITIVE CONTROL: any two distinct t-subsets aggregate to the same credential" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0xABCD);
    const kk = try keys.keygen(allocator, prng.random(), 2, 3, 5); // t=3, n=5
    defer kk.deinit(allocator);
    const attrs = [_]Fr{ frOf(42), frOf(99) };
    const h = p.commonBase(&attrs);

    const subsetA = [_]cred.PartialCredential{
        partialSignMech(kk.sk_shares[0], h, &attrs),
        partialSignMech(kk.sk_shares[2], h, &attrs),
        partialSignMech(kk.sk_shares[4], h, &attrs),
    };
    const idxA = [_]u64{ subsetA[0].index, subsetA[1].index, subsetA[2].index };
    const subsetB = [_]cred.PartialCredential{
        partialSignMech(kk.sk_shares[1], h, &attrs),
        partialSignMech(kk.sk_shares[2], h, &attrs),
        partialSignMech(kk.sk_shares[3], h, &attrs),
    };
    const idxB = [_]u64{ subsetB[0].index, subsetB[1].index, subsetB[2].index };

    const credA = try BrokenCoconut.aggregateLagrange(&idxA, &subsetA);
    const credB = try BrokenCoconut.aggregateLagrange(&idxB, &subsetB);
    try std.testing.expect(g1Eql(credA.s, credB.s)); // same credential regardless of quorum
    try std.testing.expect(cred.psVerifyPlain(kk.master_vk, credA, &attrs));
}

// ── GATED end-to-end anchor + soundness controls (SKIP until core lands) ─────

test "ANCHOR (gated): threshold-issue → aggregate → show → verify PASSES" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 3);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0x1234);
    const kk = try keys.keygen(allocator, prng.random(), 3, 2, 4);
    defer kk.deinit(allocator);

    const attrs = [_]Fr{ frOf(1), frOf(2), frOf(3) };
    const h = p.commonBase(&attrs);

    const partials = [_]cred.PartialCredential{
        try cred.signPartial(kk.sk_shares[0], h, &attrs),
        try cred.signPartial(kk.sk_shares[2], h, &attrs),
    };
    const credential = try cred.aggregateCredential(allocator, &partials, 2);
    try std.testing.expect(cred.psVerifyPlain(kk.master_vk, credential, &attrs));

    // Disclose attribute 0, hide 1 and 2.
    const disclosed = [_]bool{ true, false, false };
    const proof = try cred.proveCredential(allocator, prng.random(), p, kk.master_vk, credential, &attrs, &disclosed);
    defer proof.deinit(allocator);

    const disclosed_values = [_]Fr{attrs[0]};
    try std.testing.expect(try cred.verifyCredential(allocator, p, kk.master_vk, proof, &disclosed_values));
}

test "SOUNDNESS (gated): tampered credential / wrong disclosed value / mutated challenge / forged attribute all REJECTED" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0x9999);
    const kk = try keys.keygen(allocator, prng.random(), 2, 2, 3);
    defer kk.deinit(allocator);

    const attrs = [_]Fr{ frOf(11), frOf(22) };
    const h = p.commonBase(&attrs);
    const partials = [_]cred.PartialCredential{
        try cred.signPartial(kk.sk_shares[0], h, &attrs),
        try cred.signPartial(kk.sk_shares[1], h, &attrs),
    };
    const credential = try cred.aggregateCredential(allocator, &partials, 2);
    const disclosed = [_]bool{ true, false };
    const proof = try cred.proveCredential(allocator, prng.random(), p, kk.master_vk, credential, &attrs, &disclosed);
    defer proof.deinit(allocator);

    // 1. wrong disclosed value → reject
    const wrong_disclosed = [_]Fr{frOf(999)};
    try std.testing.expect(!try cred.verifyCredential(allocator, p, kk.master_vk, proof, &wrong_disclosed));

    // 2. mutated Fiat-Shamir challenge → reject
    var tampered = proof;
    tampered.challenge = proof.challenge.add(Fr.one);
    const good_disclosed = [_]Fr{attrs[0]};
    try std.testing.expect(!try cred.verifyCredential(allocator, p, kk.master_vk, tampered, &good_disclosed));

    // 3. honest proof still verifies (control for the above)
    try std.testing.expect(try cred.verifyCredential(allocator, p, kk.master_vk, proof, &good_disclosed));

    // 4. forged UNDISCLOSED attribute → reject. The prover builds a FULLY
    // self-consistent show proof over a credential it holds (real m = [11,22])
    // but lies about the HIDDEN attribute m₁ (claims 999, holds 22). The NIZK
    // is internally consistent — κ commits to the forged [11,999], the
    // responses are computed against it, so the Fiat-Shamir challenge recomputes
    // and the response equations pass — yet σ₂' still comes from the credential
    // on the REAL vector. The PS pairing equation e(σ₁',κ)==e(σ₂'·ν,g2) is the
    // backstop that binds the credential to the claimed attributes and REJECTS.
    const forged_attrs = [_]Fr{ frOf(11), frOf(999) };
    const forged = try cred.proveCredential(allocator, prng.random(), p, kk.master_vk, credential, &forged_attrs, &disclosed);
    defer forged.deinit(allocator);
    try std.testing.expect(!try cred.verifyCredential(allocator, p, kk.master_vk, forged, &good_disclosed));
}

test "THRESHOLD (gated): fewer than t partials fails aggregation" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0x2468);
    const kk = try keys.keygen(allocator, prng.random(), 2, 3, 5); // t=3
    defer kk.deinit(allocator);
    const attrs = [_]Fr{ frOf(7), frOf(8) };
    const h = p.commonBase(&attrs);
    const too_few = [_]cred.PartialCredential{
        try cred.signPartial(kk.sk_shares[0], h, &attrs),
        try cred.signPartial(kk.sk_shares[1], h, &attrs),
    };
    try std.testing.expectError(error.NotEnoughPartials, cred.aggregateCredential(allocator, &too_few, 3));
}

fn frOf(v: u64) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], v, .big);
    return Fr.fromBytes(buf) catch unreachable;
}

fn g1Eql(a: g1.Affine, b: g1.Affine) bool {
    return a.x.eql(b.x) and a.y.eql(b.y) and a.infinity == b.infinity;
}
