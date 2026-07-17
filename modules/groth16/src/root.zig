// SPDX-License-Identifier: MIT
//! groth16 — a Groth16 zk-SNARK PROVER over BN254, the counterpart to the
//! sibling `bn254` module's Groth16 VERIFIER (`bn254.groth16Verify`). Given an
//! R1CS circuit, a proving key (CRS), and a satisfying witness, the prover
//! produces the 3-element proof `(πA ∈ G1, πB ∈ G2, πC ∈ G1)` that the
//! `bn254` verifier accepts. Construction: Groth 2016, "On the Size of
//! Pairing-based Non-interactive Arguments".
//!
//! **Status: Phase-1 SCAFFOLD.** The entire mechanical + math layer is REAL
//! and heavily anchored:
//!   - `field`  — `Fr` helpers over `bn254`'s scalar field.
//!   - `poly`   — dense `Fr[x]` arithmetic + division by `Z(x) = x^n − 1`.
//!   - `domain` — radix-2 evaluation domain (`n`-th roots of unity, 2-adicity
//!                28), vanishing polynomial.
//!   - `fft`    — radix-2 NTT / inverse-NTT over `Fr` + FFT polynomial
//!                multiplication (round-trip + `== schoolbook` anchored).
//!   - `msm`    — multi-scalar multiplication in `G1`/`G2` (naive; `== naive`
//!                is the anchor).
//!   - `r1cs`   — rank-1 constraint system + witness satisfaction (the QAP
//!                divisibility oracle).
//!   - `qap`    — R1CS→QAP interpolation + `A·B−C` divisibility by `Z` — which
//!                equals R1CS satisfaction, the self-contained teeth-test.
//!
//! The one part NOT implemented is the **prover core** — `prover.setup` (toy
//! trusted setup) and `prover.prove` (proof assembly) — gated behind
//! `gate.prover_core_implemented` (`false`), so they `@panic` and the
//! end-to-end test SKIPs. That core is an **Opus** task, not a Fable one: the
//! `bn254` verifier is a COMPLETE deterministic anchor, so any prover error is
//! caught (no self-consistent-but-wrong failure mode the way a Fable-tier core
//! has). See `gate.zig` and `SPEC.md`'s tier call.
//!
//! Deferred increments (all OUT of Phase 1 — see `SPEC.md`): snarkjs `.zkey`/
//! witness ingestion for a byte-exact external anchor, Pippenger MSM,
//! circuit/gadget DSL, PLONK/Halo2 (explicit scope non-goals), recursion.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure computation — no I/O, threads, or libc
    .role = .util,
    .concurrency = .reentrant, // value types + caller-supplied buffers, no shared state
    .model_after = "Groth16 (Groth 2016, 'On the Size of Pairing-based Non-interactive Arguments'); prover mirrors snarkjs/arkworks-groth16 over BN254, anchored by the sibling bn254 module's verifier",
    .deps = .{"bn254"}, // Fr / G1 / G2 / pairing / Groth16 verifier
};

pub const gate = @import("gate.zig");
pub const field = @import("field.zig");
pub const poly = @import("poly.zig");
pub const domain = @import("domain.zig");
pub const fft = @import("fft.zig");
pub const msm = @import("msm.zig");
pub const r1cs = @import("r1cs.zig");
pub const qap = @import("qap.zig");
pub const prover = @import("prover.zig");

// Convenience re-exports.
pub const Fr = field.Fr;
pub const Domain = domain.Domain;
pub const System = r1cs.System;
pub const Constraint = r1cs.Constraint;
pub const Term = r1cs.Term;
pub const ProvingKey = prover.ProvingKey;
pub const VerifyingKey = prover.VerifyingKey;
pub const Proof = prover.Proof;
pub const ToxicWaste = prover.ToxicWaste;
pub const KeyPair = prover.KeyPair;
pub const Randomizers = prover.Randomizers;
pub const setup = prover.setup;
pub const prove = prover.prove;
pub const freeKeyPair = prover.freeKeyPair;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's tests
// into the test binary — every submodule (and the harness) must be named here.
test {
    _ = gate;
    _ = field;
    _ = poly;
    _ = domain;
    _ = fft;
    _ = msm;
    _ = r1cs;
    _ = qap;
    _ = prover;
    _ = @import("harness_test.zig");
}

test "meta names the Groth16 construction and the bn254 dep" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Groth16") != null);
    try std.testing.expectEqualStrings("bn254", meta.deps[0]);
}
