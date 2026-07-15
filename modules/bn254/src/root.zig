// SPDX-License-Identifier: MIT
//! bn254 — BN254 (alt-bn128), the pairing-friendly elliptic curve
//! behind Ethereum's EIP-196/197 precompiles (`ecAdd`/`ecMul`/
//! `ecPairing`, addresses `0x06`/`0x07`/`0x08`) and Groth16 zk-SNARK
//! verification. **This module is Parts 1-2 of a multi-part arc**: the
//! base field `Fp`, its extension tower `Fp2`/`Fp6`/`Fp12`, and the
//! scalar field `Fr` — the foundation for the pairing groups `G1`/`G2`
//! (a later part), the optimal-ate pairing itself, the EIP-196/197
//! precompile semantics, and a Groth16 verifier (see `README.md` for
//! the full planned arc).
//!
//! **Status: Parts 1-2 complete.** Every field-tower operation is
//! implemented and tested; NO group arithmetic, NO pairing, NO
//! precompile wiring yet. This module was built by careful, verified
//! ADAPTATION of the sibling `bls12_381` module (same `std.crypto.ff`-
//! backed `Fp`/`Fr` construction, same tower-arithmetic formula shapes
//! from Devegili et al. and Adj & Rodriguez-Henriquez) with BN254's own
//! field/curve constants substituted in and independently verified —
//! see `SPEC.md`'s "Model-after + seed" and "Verification performed"
//! sections for the exact sources and cross-checks. Every constant is
//! also pinned against byte-exact known-answer test vectors computed
//! independently in Python (not transcribed from any third-party
//! library) — see the KAT tests in `fp2.zig`/`fp6.zig`/`fp12.zig` and
//! `SPEC.md`.

const std = @import("std");

pub const fp = @import("fp.zig");
pub const fp2 = @import("fp2.zig");
pub const fp6 = @import("fp6.zig");
pub const fp12 = @import("fp12.zig");
pub const scalar = @import("scalar.zig");

pub const Fp = fp.Fp;
pub const Fp2 = fp2.Fp2;
pub const Fp6 = fp6.Fp6;
pub const Fp12 = fp12.Fp12;
pub const Fr = scalar.Fr;

pub const meta = .{
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
