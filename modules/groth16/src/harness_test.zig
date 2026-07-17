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

test "end-to-end anchor: prove -> bn254.groth16Verify accepts; tamper -> rejects (GATED)" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;

    // When the Opus core lands, this body becomes:
    //   const cons = r1cs.example.constraints();
    //   const sys  = r1cs.example.system(&cons);
    //   const w    = r1cs.example.goodWitness();
    //   const kp   = prover.setup(2, sys, toxic_tau);
    //   const pf   = prover.prove(2, kp.pk, sys, &w, .{ .r = r, .s = s });
    //   const pub  = w[1..2];                       // the public input(s)
    //   try std.testing.expect(try bn254.groth16Verify(kp.vk, pf, pub));
    //   // tamper: flip a proof coordinate / a public input -> verify FALSE
    _ = prover;
    unreachable;
}
