// SPDX-License-Identifier: MIT

//! fast_core — the GATED irreducible x86-64 field core (SCAFFOLD: panic stubs).
//!
//! The Fable core phase will fill this with a hand-written
//! `MULX/ADCX/ADOX` dual-carry-chain P-256 base-field multiply and square: a
//! 256×256→512-bit product over four full 2^64 limbs, followed by the
//! special-prime fold `2^256 ≡ M (mod p)` with `M = 2^224 − 2^192 − 2^96 + 1`
//! back into 256 bits. It is the single biggest, most curve-specific win — every
//! point operation (and therefore every scalar multiply, sign, and verify) is
//! dominated by field multiplies.
//!
//! ## Contract (do NOT change without updating the field dispatch + differential)
//!
//! `fieldMul(z, a, b)` computes `z = a·b mod p` and `fieldSq(z, a)` computes
//! `z = a² mod p`, where `a`, `b`, `z` are the same `[4]u64` little-endian,
//! FULLY REDUCED (`< p`) limbs the portable `field.mulPortable` /
//! `field.sqPortable` consume and return. The result MUST be `< p` and
//! byte-for-byte identical to the portable Solinas reduction — enforced by the
//! gated differential in `oracle_test.zig` (which goes live only once
//! `gate.field_asm_implemented` is flipped and the stub replaced).
//!
//! ## The P-256 fold vs k256's fold (the curve-specific hazard)
//!
//! k256's secp256k1 fold multiplies the high half by a TINY constant
//! `c = 2^32 + 977`, so a single `MULX` + short add chain per fold and only ~4
//! folds. P-256's fold multiplier `M = 2^224 − 2^192 − 2^96 + 1` is ~2^224 —
//! a WIDE multiply, and the excess shrinks only ~32 bits per fold. Two equivalent
//! limb-level shapes for the Fable author:
//!   * **wide-fold** — mirror the portable `field.reduceWide`: repeatedly
//!     `lo += M·hi` on limbs. Fewer distinct code paths, but many folds.
//!   * **word-shuffle (the classic nistz256 reduction)** — express the reduction
//!     as `s1 + 2·s2 + 2·s3 + s4 + s5 − s6 − s7 − s8 − s9 (mod p)` over the
//!     sixteen 32-bit product words c0..c15 (each s_i a fixed permutation of the
//!     high words, with the documented signs), then a bounded sequence of
//!     conditional add/subtract of `p`. Fewer folds, but SIGNED intermediates —
//!     the borrows from the four subtracted terms are the error-prone spot, and
//!     the final `[0, p)` canonicalisation needs a masked (branch-free) select,
//!     not a data-dependent loop.
//! Either way the portable `field.reduceWide` is the bit-exact oracle.
//!
//! ## Constant-time contract (for the eventual core)
//!
//! Field mul/sq run on SECRET data (signing). Both blocks must be straight-line
//! code with zero branches; no secret-indexed loads/stores; the final reduce a
//! masked select. All value-carrying instructions in the DIT set. Register/flag
//! discipline transfers from `montint/src/asm_core.zig` and `k256/src/fast_core.zig`
//! (AT&T suffixes; `MULX` touches no flag; `ADCX`/`ADOX` on the two carry chains;
//! `movl $imm` preserves flags where a chain is live).

const std = @import("std");
const builtin = @import("builtin");

/// True at comptime iff this target can host the amd64 field core (x86-64 with
/// the ADX + BMI2 feature flags that supply `ADCX/ADOX` and `MULX`). On every
/// other target the dispatch in `field.zig` stays on the portable Solinas path
/// forever, regardless of the gate flag.
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);

/// `z = a·b mod p` over four full 2^64 limbs (see the module doc for the full
/// contract). GATED Fable core — a panic stub in this scaffold. It is never
/// reached at runtime while `gate.field_asm_implemented` is `false` (the field
/// dispatcher and the differential harness both comptime-guard on the gate), so
/// the stub cannot fire; it exists to fix the signature the core must satisfy.
pub fn fieldMul(z: *[4]u64, a: *const [4]u64, b: *const [4]u64) void {
    _ = z;
    _ = a;
    _ = b;
    @panic("TODO(fable/core): P-256 amd64 MULX/ADX field multiply + Solinas fold");
}

/// `z = a² mod p` over four full 2^64 limbs. A dedicated square (off-diagonal
/// products once, doubled) is ~1.5× cheaper than a general multiply. GATED
/// Fable core — a panic stub in this scaffold (see `fieldMul`).
pub fn fieldSq(z: *[4]u64, a: *const [4]u64) void {
    _ = z;
    _ = a;
    @panic("TODO(fable/core): P-256 amd64 MULX/ADX field square + Solinas fold");
}
