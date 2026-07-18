// SPDX-License-Identifier: MIT

//! fast_core — the GATED irreducible x86-64 field core (SCAFFOLD STUB).
//!
//! This file is the home of the hand-written `MULX/ADCX/ADOX` dual-carry-chain
//! secp256k1 base-field multiply and square: a 256×256→512-bit product over four
//! full 2^64 limbs, followed by the special-prime fold `2^256 ≡ 2^32 + 977
//! (mod p)` back into 256 bits. It is the single biggest, most curve-specific
//! win — every point operation (and therefore every scalar multiply, sign, and
//! verify) is dominated by field multiplies.
//!
//! In this SCAFFOLD phase both entry points `@panic("TODO(fable/core)")`: they
//! are never reached, because `field.zig` only dispatches here when
//! `gate.field_asm_implemented and supported`, and the gate flag is `false`.
//! The portable Solinas path in `field.zig` (byte-exact vs
//! `std.crypto.ecc.Secp256k1.Fe`) runs instead. A Fable agent replaces the two
//! panics with the asm, flips `gate.field_asm_implemented`, and the
//! `fast_core`-vs-portable differential in `oracle_test.zig` lights up.
//!
//! ## Contract (do NOT change without updating the field dispatch + differential)
//!
//! `fieldMul(z, a, b)` computes `z = a·b mod p` and `fieldSq(z, a)` computes
//! `z = a² mod p`, where `a`, `b`, `z` are the same `[4]u64` little-endian,
//! FULLY REDUCED (`< p`) limbs the portable `field.mulPortable` / `field.sqPortable`
//! consume and return. `z` may alias neither `a` nor `b` (`field.zig` passes a
//! fresh out-buffer). The result MUST be `< p` and byte-for-byte identical to the
//! portable Solinas reduction — enforced by the differential.
//!
//! ## Representation note for the core author (the field-choice rationale)
//!
//! k256 stores the field as **four full 2^64 limbs** (not libsecp256k1's portable
//! 5×52-bit limbs). Rationale, and its asm implications, are in `SPEC.md §Field
//! representation`: full 2^64 limbs are what `MULX`/`ADX` want (each `MULX`
//! consumes/produces a full 64-bit word; a 4×4 limb product is 16 `MULX` in two
//! carry chains), whereas 5×52 is tuned for *portable* C (its spare 12 bits/limb
//! delay carry propagation without hardware add-with-carry). Since the whole
//! point of this core is to USE `ADCX/ADOX`, 4×64 is the right substrate — the
//! same choice `montint`'s asm core made, and the register/flag discipline notes
//! in `montint/src/asm_core.zig` (AT&T suffixes, `dec` preserves CF, `MULX`
//! touches no flag, fold OF before loop control) apply directly to the fold.

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
/// contract). Dispatched iff `supported and gate.field_asm_implemented`.
pub fn fieldMul(z: *[4]u64, a: *const [4]u64, b: *const [4]u64) void {
    _ = z;
    _ = a;
    _ = b;
    @panic("TODO(fable/core): k256 MULX/ADX field multiply not implemented");
}

/// `z = a² mod p` over four full 2^64 limbs. A dedicated square is ~1.5× cheaper
/// than a general multiply (each off-diagonal product computed once and doubled).
/// Dispatched iff `supported and gate.field_asm_implemented`.
pub fn fieldSq(z: *[4]u64, a: *const [4]u64) void {
    _ = z;
    _ = a;
    @panic("TODO(fable/core): k256 MULX/ADX field square not implemented");
}
