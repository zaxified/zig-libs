// SPDX-License-Identifier: MIT
//! bn254 — BN254 (alt-bn128), the pairing-friendly elliptic curve
//! behind Ethereum's EIP-196/197 precompiles (`ecAdd`/`ecMul`/
//! `ecPairing`, addresses `0x06`/`0x07`/`0x08`) and Groth16 zk-SNARK
//! verification. **This module is the COMPLETE Parts 1-6 arc**: the
//! base field `Fp`, its extension tower `Fp2`/`Fp6`/`Fp12`, the scalar
//! field `Fr` (Parts 1-2), the pairing groups `G1`/`G2` (Part 3), the
//! optimal-ate pairing itself (Part 4, `pairing.zig`), the EIP-196/197
//! EVM precompile entry points (Part 5, `precompiles.zig`), and the
//! Groth16 zk-SNARK verifier (Part 6, `groth16.zig`) — pure composition
//! over Parts 1-5's pairing/group arithmetic (see `README.md` for the
//! full arc).
//!
//! **Status: Parts 1-6 complete.** Every field-tower operation, `G1`/`G2`
//! Jacobian group arithmetic, scalar multiplication, on-curve/subgroup-
//! membership checks, and EIP-196/197 (de)serialization (Parts 1-3), the
//! optimal-ate pairing itself (Part 4, `pairing.zig`) — `Gt`/
//! `PairingPair`, the comptime-derived-and-KAT-pinned `6x+2` loop
//! parameter, the `millerLoop` core (its `6x+2` walk with the BN-specific
//! Frobenius tail) and the `finalExponentiation` core (curve-generic easy
//! part + the BN-specific exact-`d` hard-part addition chain), and
//! `multiMillerLoop`/`pairing`/`pairingCheck` wiring — implemented and
//! tested, byte-exact against `ethereum/py_ecc` (`gate
//! .pairing_core_implemented` is now `true`, so the full pairing test tier
//! — bilinearity, non-degeneracy, `e^r==1`, `pairingCheck`, and the three
//! py_ecc KAT vectors — runs); and now `ecAdd`/`ecMul`/`ecPairing`
//! themselves (Part 5, `precompiles.zig`) — pure composition over Parts
//! 1-4 (calldata padding/truncation, point decode, group op, re-encode),
//! byte-exact against the OFFICIAL `ethereum/go-ethereum`
//! `core/vm/testdata/precompiles/*.json` conformance vectors (49 vectors
//! across all three precompiles, both the `ecPairing` true AND false
//! paths). This module was built by careful, verified ADAPTATION of
//! the sibling `bls12_381` module (same `std.crypto.ff`-backed `Fp`/`Fr`
//! construction, same tower-arithmetic formula shapes from Devegili et
//! al. and Adj & Rodriguez-Henriquez, same Jacobian point-arithmetic
//! formulas from `g1.zig`/`g2.zig`, same pairing STRUCTURE from
//! `bls12_381/src/pairing.zig`) with BN254's own field/curve constants
//! substituted in and independently verified — see `SPEC.md`'s
//! "Model-after + seed" and "Verification performed" sections for the
//! exact sources and cross-checks. Every constant is also pinned against
//! byte-exact known-answer test vectors computed independently in Python
//! (not transcribed from any third-party library's SOURCE — Part 4's KAT
//! numeric OUTPUTS were sourced from `ethereum/py_ecc`, see `pairing.zig`'s
//! module doc comment) — see the KAT tests in `fp2.zig`/`fp6.zig`/
//! `fp12.zig`/`g1.zig`/`g2.zig`/`pairing.zig` and `SPEC.md`.

const std = @import("std");

pub const fp = @import("fp.zig");
pub const fp2 = @import("fp2.zig");
pub const fp6 = @import("fp6.zig");
pub const fp12 = @import("fp12.zig");
pub const scalar = @import("scalar.zig");
pub const g1 = @import("g1.zig");
pub const g2 = @import("g2.zig");
pub const gate = @import("gate.zig");
pub const pairing = @import("pairing.zig");
pub const precompiles = @import("precompiles.zig");
pub const groth16 = @import("groth16.zig");

pub const Fp = fp.Fp;
pub const Fp2 = fp2.Fp2;
pub const Fp6 = fp6.Fp6;
pub const Fp12 = fp12.Fp12;
pub const Fr = scalar.Fr;
pub const G1 = g1;
pub const G2 = g2;
pub const Gt = pairing.Gt;

// Part 5 — EVM precompile entry points (EIP-196/197), re-exported at the
// top level for convenience (see precompiles.zig's module doc comment):
pub const ecAdd = precompiles.ecAdd;
pub const ecMul = precompiles.ecMul;
pub const ecPairing = precompiles.ecPairing;
pub const ecPairingCheck = precompiles.ecPairingCheck;
pub const PrecompileError = precompiles.PrecompileError;

// Part 6 — Groth16 zkSNARK verifier, re-exported at the top level (see
// groth16.zig's module doc comment):
pub const Groth16VerifyingKey = groth16.VerifyingKey;
pub const Groth16Proof = groth16.Proof;
pub const groth16Verify = groth16.verify;
pub const Groth16Error = groth16.Groth16Error;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing
    .concurrency = .reentrant, // every type is a plain value type, no shared state
    .model_after = "BN254 / alt-bn128 (EIP-196/197) field tower; std.crypto.ff supplies the constant-time Montgomery modular arithmetic Fp/Fr are built on — same construction as the sibling bls12_381 module, adapted to BN254's modulus/non-residues",
    .deps = .{}, // std only (std.crypto.ff)
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too (the dark-tests rule; see CONVENTIONS.md).
test {
    _ = fp;
    _ = fp2;
    _ = fp6;
    _ = fp12;
    _ = scalar;
    _ = g1;
    _ = g2;
    _ = gate;
    _ = pairing;
    _ = precompiles;
    _ = groth16;
}

test "meta.model_after names BN254/alt-bn128" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BN254") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "EIP-196/197") != null);
}

test "field tower encoded widths compose correctly" {
    try std.testing.expectEqual(@as(usize, 32), Fp.encoded_bytes);
    try std.testing.expectEqual(@as(usize, 64), Fp2.encoded_bytes);
    try std.testing.expectEqual(@as(usize, 192), Fp6.encoded_bytes);
    try std.testing.expectEqual(@as(usize, 384), Fp12.encoded_bytes);
    try std.testing.expectEqual(@as(usize, 32), Fr.encoded_bytes);
}

test "Fp and Fr are DIFFERENT 254-bit primes sharing the same 32-byte container" {
    // Deliberate BN254 quirk vs. bls12_381 (where Fp is 381 bits/48
    // bytes and Fr is 255 bits/32 bytes, two different container
    // widths): BN254's p and r are both exactly 254 bits, so both
    // fields use the identical 32-byte container — but they are still
    // DISTINCT moduli (Fp is not Fr).
    try std.testing.expectEqual(@as(usize, 254), fp.modulus.bits());
    try std.testing.expectEqual(@as(usize, 254), scalar.modulus.bits());
    try std.testing.expect(!std.mem.eql(u8, &fp.p_bytes, &scalar.r_bytes));
}
