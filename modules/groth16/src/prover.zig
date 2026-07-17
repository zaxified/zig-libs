// SPDX-License-Identifier: MIT
//! The Groth16 PROVER — `setup` (a test-only toy CRS/trusted setup) and
//! `prove` (the 3-element proof assembly `πA ∈ G1, πB ∈ G2, πC ∈ G1`). This
//! is the one part of the module the Phase-1 SCAFFOLD does NOT implement: both
//! functions are gated behind `gate.prover_core_implemented` and `@panic`
//! until the core lands. See `gate.zig` for why this is an **Opus** flag (the
//! sibling `bn254` Groth16 verifier is a complete deterministic anchor), not a
//! Fable one.
//!
//! What IS real here: `brokenProof`, a deliberately-wrong "prover" output used
//! as the harness's positive control — `bn254.groth16Verify` REJECTS it,
//! proving the end-to-end anchor has teeth before `prove` exists.
//!
//! ## Proof/key types
//!
//! The output proof type is the sibling verifier's own `bn254.Groth16Proof`
//! (`{a: G1, b: G2, c: G1}`), so `prove`'s result feeds straight into
//! `bn254.groth16Verify` — the anchor. The `VerifyingKey` is likewise
//! `bn254.Groth16VerifyingKey`. `ProvingKey` (the CRS the prover consumes) is
//! defined here.

const std = @import("std");
const bn254 = @import("bn254");
const gate = @import("gate.zig");
const field = @import("field.zig");
const r1cs = @import("r1cs.zig");
const Fr = field.Fr;

const G1 = bn254.G1;
const G2 = bn254.G2;

/// The verifier's proof type, re-exported — `prove` produces exactly this so
/// it can be handed to `bn254.groth16Verify` (the anchor).
pub const Proof = bn254.Groth16Proof;

/// The verifier's key type, re-exported — `setup` produces exactly this.
pub const VerifyingKey = bn254.Groth16VerifyingKey;

/// The Groth16 proving key (CRS) the prover consumes. Standard Groth-2016 /
/// snarkjs `.zkey` layout: precomputed group-element "query" vectors indexed
/// by witness variable, plus the `H(x)` bases. Populated by `setup` (gated)
/// or ingested from a snarkjs `.zkey` (a deferred Phase-3 increment — see
/// `SPEC.md`). All slices are borrowed; the prover never mutates them.
pub const ProvingKey = struct {
    alpha_g1: G1.Affine,
    beta_g1: G1.Affine,
    delta_g1: G1.Affine,
    beta_g2: G2.Affine,
    delta_g2: G2.Affine,
    /// `A_i(τ)·G` bases, one per witness variable.
    a_query: []const G1.Affine,
    /// `B_i(τ)·G` bases in `G1`, one per witness variable.
    b_g1_query: []const G1.Affine,
    /// `B_i(τ)·G` bases in `G2`, one per witness variable.
    b_g2_query: []const G2.Affine,
    /// The private-witness `C` bases `((β·A_i + α·B_i + C_i)/δ)·G`.
    l_query: []const G1.Affine,
    /// `H(x)` bases `(τ^i·Z(τ)/δ)·G`, `n−1` of them for a size-`n` domain.
    h_query: []const G1.Affine,
    /// Domain size `n` this CRS was generated for.
    domain_size: usize,
};

/// Zero-knowledge randomizers `r, s ∈ Fr` for a single proof. Distinct random
/// draws per proof; fixing them (as a test may) makes `prove` deterministic —
/// the hook for a future byte-exact snarkjs cross-check.
pub const Randomizers = struct { r: Fr, s: Fr };

/// **GATED (Opus core).** Toy, INSECURE trusted setup: samples a CRS for the
/// R1CS over `Domain(n)` from an explicit toxic-waste `tau` (test-only — a
/// real deployment runs an MPC ceremony). Produces a matching
/// `ProvingKey`/`VerifyingKey` pair such that a proof from `prove` verifies
/// under `bn254.groth16Verify`.
///
/// Panics until `gate.prover_core_implemented` is set. See `SPEC.md`.
pub fn setup(comptime n: usize, sys: r1cs.System, tau: Fr) struct { pk: ProvingKey, vk: VerifyingKey } {
    _ = n;
    _ = sys;
    _ = tau;
    if (!gate.prover_core_implemented)
        @panic("groth16.setup: prover core not implemented (Opus core; gate.prover_core_implemented == false — see gate.zig/SPEC.md)");
    unreachable; // replaced by the real toy-setup when the gate flips
}

/// **GATED (Opus core).** Produces a Groth16 proof for `witness` under `pk`.
/// The result is a `bn254.Groth16Proof` that `bn254.groth16Verify` accepts
/// for the matching `VerifyingKey` and public inputs — the end-to-end anchor.
///
/// Panics until `gate.prover_core_implemented` is set. See `SPEC.md`.
pub fn prove(comptime n: usize, pk: ProvingKey, sys: r1cs.System, witness: []const Fr, rand: Randomizers) Proof {
    _ = n;
    _ = pk;
    _ = sys;
    _ = witness;
    _ = rand;
    if (!gate.prover_core_implemented)
        @panic("groth16.prove: prover core not implemented (Opus core; gate.prover_core_implemented == false — see gate.zig/SPEC.md)");
    unreachable; // replaced by the real proof assembly when the gate flips
}

/// REAL positive control: a deliberately-WRONG "proof" (the group generators,
/// which do not satisfy any real circuit's pairing equation), used to prove
/// the anchor rejects garbage. NOT a real prover — see the harness test.
pub fn brokenProof() Proof {
    return .{
        .a = G1.Affine.generator,
        .b = G2.Affine.generator,
        .c = G1.Affine.generator,
    };
}

/// REAL: a well-formed-but-bogus verifying key (generator points) for the
/// positive control. Not from any real setup — only used to show
/// `bn254.groth16Verify` returns `false` for a non-proof.
pub fn bogusVerifyingKey(ic: []const G1.Affine) VerifyingKey {
    return .{
        .alpha_g1 = G1.Affine.generator,
        .beta_g2 = G2.Affine.generator,
        .gamma_g2 = G2.Affine.generator,
        .delta_g2 = G2.Affine.generator,
        .ic = ic,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

test "positive control: bn254 verifier REJECTS the broken proof (anchor has teeth)" {
    // A bogus vk with 2 IC points (1 public input) and the broken proof.
    const ic = [_]G1.Affine{ G1.Affine.generator, G1.Affine.generator };
    const vk = bogusVerifyingKey(&ic);
    const proof = brokenProof();
    const public = [_]Fr{field.frFromU64(1)};
    const ok = try bn254.groth16Verify(vk, proof, &public);
    try std.testing.expect(!ok); // MUST reject — the equation cannot hold
}

test "setup is gated (SKIP until the Opus core lands)" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;
    // When the gate flips, a real end-to-end setup+prove+verify test replaces
    // this skip (see harness_test.zig's gated end-to-end test).
    unreachable;
}
