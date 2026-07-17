// SPDX-License-Identifier: MIT
//! End-to-end verification harness for the Groth16 prover, anchored by the
//! sibling `bn254` module's Groth16 VERIFIER. Two tiers:
//!
//!   1. **Runs today (teeth without the core):** the sub-anchors are already
//!      exercised in their own files — FFT round-trip + `mulViaFFT ==
//!      schoolbook` (`fft.zig`), MSM `== naive` (`msm.zig`), QAP divisibility
//!      tracks R1CS satisfaction (`qap.zig`), and the deliberately-broken
//!      "prover" is REJECTED by `bn254.groth16Verify` (`prover.zig`). This
//!      file adds the end-to-end wiring shape and the cross-stack consistency
//!      check.
//!   2. **Gated (Opus core):** `prove(setup(…)) → bn254.groth16Verify ==
//!      true`, plus tamper cases → `false`. SKIP until
//!      `gate.prover_core_implemented`.

const std = @import("std");
const bn254 = @import("bn254");
const gate = @import("gate.zig");
const field = @import("field.zig");
const qap = @import("qap.zig");
const r1cs = @import("r1cs.zig");
const prover = @import("prover.zig");
const Fr = field.Fr;

test "cross-stack consistency: QAP divisibility == R1CS satisfaction (the ungated anchor)" {
    // This is the strongest thing provable WITHOUT the prover core: the whole
    // FFT/interpolation/vanishing-division stack is correct iff its
    // divisibility verdict matches the independent R1CS satisfaction oracle,
    // on both a satisfying and a non-satisfying witness.
    const cons = r1cs.example.constraints();
    const sys = r1cs.example.system(&cons);
    const good = r1cs.example.goodWitness();
    const bad = r1cs.example.badWitness();
    try std.testing.expectEqual(sys.isSatisfied(&good), qap.checkDivisible(2, sys, &good));
    try std.testing.expectEqual(sys.isSatisfied(&bad), qap.checkDivisible(2, sys, &bad));
}

// ── the non-trivial end-to-end circuit ──────────────────────────────────────
//
// Prove knowledge of private `x, y` such that three PUBLIC outputs hold:
//   out1 = x²,  out2 = y²,  out3 = (x + y)²
// with the last checked via out3 = out1 + out2 + 2·xy over a private product
// wire `xy`. Four constraints, THREE public inputs, three private wires — so
// both the `ic`/public-input accumulation (γ path) AND the private `l_query`
// (δ path) are genuinely exercised, unlike a single a·b=c circuit.
//
// Witness layout (public wires first, wire 0 = constant 1):
//   w = [ 1, out1, out2, out3, x, y, xy ]   (num_vars = 7, num_public = 3)
// Constraints:
//   C0:  x · y   = xy      a={w4} b={w5} c={w6}
//   C1:  x · x   = out1    a={w4} b={w4} c={w1}
//   C2:  y · y   = out2    a={w5} b={w5} c={w2}
//   C3: (out1 + out2 + 2·xy) · 1 = out3   a={w1,w2,w6,w6} b={w0} c={w3}
// (the 2·xy is expressed as the xy term listed twice with coeff 1 — every
// coefficient is `Fr.one`, a comptime constant, so the sparse `Term` arrays
// get static storage rather than dangling as stack temporaries).
const nt_num_vars: usize = 7;
const nt_num_public: usize = 3;
const nt_domain: usize = 4; // ≥ 4 constraints, power of two

fn ntConstraints() [4]r1cs.Constraint {
    const one = Fr.one;
    return .{
        .{
            .a = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 6, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 1, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 2, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{
                .{ .index = 1, .coeff = one },
                .{ .index = 2, .coeff = one },
                .{ .index = 6, .coeff = one },
                .{ .index = 6, .coeff = one },
            },
            .b = &[_]r1cs.Term{.{ .index = 0, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 3, .coeff = one }},
        },
    };
}

/// Satisfying witness for x=3, y=4: xy=12, out1=9, out2=16, out3=49.
fn ntWitness() [7]Fr {
    return .{
        Fr.one,
        field.frFromU64(9), // out1 = x²
        field.frFromU64(16), // out2 = y²
        field.frFromU64(49), // out3 = (x+y)²
        field.frFromU64(3), // x
        field.frFromU64(4), // y
        field.frFromU64(12), // xy
    };
}

fn ntToxicWaste() prover.ToxicWaste {
    return .{
        .tau = field.frFromU64(7),
        .alpha = field.frFromU64(11),
        .beta = field.frFromU64(13),
        .gamma = field.frFromU64(17),
        .delta = field.frFromU64(19),
    };
}

test "end-to-end anchor: prove -> bn254.groth16Verify ACCEPTS (4 constraints, 3 public inputs)" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    const cons = ntConstraints();
    const sys = r1cs.System{ .num_vars = nt_num_vars, .constraints = &cons };
    const w = ntWitness();
    try std.testing.expect(sys.isSatisfied(&w)); // sanity: witness is valid

    const kp = try prover.setup(nt_domain, alloc, sys, nt_num_public, ntToxicWaste());
    defer prover.freeKeyPair(alloc, kp);
    // vk shape: ic.len == num_public + 1.
    try std.testing.expectEqual(nt_num_public + 1, kp.vk.ic.len);

    const proof = prover.prove(nt_domain, kp.pk, sys, nt_num_public, &w, .{
        .r = field.frFromU64(123),
        .s = field.frFromU64(456),
    });

    const public = w[1 .. nt_num_public + 1]; // [out1, out2, out3]
    try std.testing.expect(try bn254.groth16Verify(kp.vk, proof, public));
}

test "end-to-end tamper: flipped proof coordinate / wrong public input -> REJECTS" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    const cons = ntConstraints();
    const sys = r1cs.System{ .num_vars = nt_num_vars, .constraints = &cons };
    const w = ntWitness();

    const kp = try prover.setup(nt_domain, alloc, sys, nt_num_public, ntToxicWaste());
    defer prover.freeKeyPair(alloc, kp);

    const proof = prover.prove(nt_domain, kp.pk, sys, nt_num_public, &w, .{
        .r = field.frFromU64(123),
        .s = field.frFromU64(456),
    });
    const public = w[1 .. nt_num_public + 1];
    // Baseline: the untampered proof verifies.
    try std.testing.expect(try bn254.groth16Verify(kp.vk, proof, public));

    // Tamper 1: negate πA (on-curve, wrong point) -> reject.
    {
        var bad = proof;
        bad.a = bn254.G1.Jacobian.fromAffine(bad.a).negate().toAffine();
        try std.testing.expect(!(try bn254.groth16Verify(kp.vk, bad, public)));
    }
    // Tamper 2: negate πC -> reject.
    {
        var bad = proof;
        bad.c = bn254.G1.Jacobian.fromAffine(bad.c).negate().toAffine();
        try std.testing.expect(!(try bn254.groth16Verify(kp.vk, bad, public)));
    }
    // Tamper 3: wrong public input (out1 off by one) -> reject.
    {
        var bad_public = [_]Fr{ public[0].add(Fr.one), public[1], public[2] };
        try std.testing.expect(!(try bn254.groth16Verify(kp.vk, proof, &bad_public)));
    }
}

test "end-to-end: a NON-satisfying witness produces a proof that is REJECTED" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    const cons = ntConstraints();
    const sys = r1cs.System{ .num_vars = nt_num_vars, .constraints = &cons };

    const kp = try prover.setup(nt_domain, alloc, sys, nt_num_public, ntToxicWaste());
    defer prover.freeKeyPair(alloc, kp);

    // Corrupt the private product wire xy (12 -> 13): the R1CS is no longer
    // satisfied, so the QAP quotient is inexact and the assembled proof must
    // NOT verify against the honest public inputs.
    var w = ntWitness();
    w[6] = field.frFromU64(13);
    try std.testing.expect(!sys.isSatisfied(&w));

    const proof = prover.prove(nt_domain, kp.pk, sys, nt_num_public, &w, .{
        .r = field.frFromU64(123),
        .s = field.frFromU64(456),
    });
    const public = ntWitness()[1 .. nt_num_public + 1]; // honest public inputs
    try std.testing.expect(!(try bn254.groth16Verify(kp.vk, proof, public)));
}
