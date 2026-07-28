// SPDX-License-Identifier: MIT

//! k256 — an asm-accelerated pure-Zig secp256k1, the fast alternative to
//! `std.crypto.ecc.Secp256k1`.
//!
//! std's secp256k1 is portable pure-Zig (fiat-crypto Montgomery field, no asm),
//! which makes it ~9–14× slower than libsecp256k1 (hand asm + GLV endomorphism +
//! wNAF). The 8 Bitcoin/Lightning modules in this repo
//! (bip340/taproot/musig2/adaptor/frost/sphinx/bolt3/bolt8) all ride it. k256 is
//! our OWN secp256k1 built for speed while keeping the zero-C/no-libc invariant:
//! the special-prime (Solinas) field reduction, the GLV endomorphism, and an
//! amd64 `MULX/ADX` field multiply, with a portable fallback everywhere. Target:
//! ~2–4× libsecp256k1 (parity with decades-tuned asm-grade C isn't expected;
//! going ~9–14×→~2–4× is the win). See `SPEC.md` for the dedup justification.
//!
//! ## Status (core phase done)
//!
//! The PORTABLE path is **real, constant-time, and byte-exact vs
//! `std.crypto.ecc.Secp256k1` + the official BIP340 vectors** — it is the
//! correctness ORACLE and the non-amd64 fallback. Both irreducible Fable cores
//! are IMPLEMENTED and gated ON (`gate.field_asm_implemented` /
//! `gate.glv_scalarmul_implemented`): the amd64 `MULX/ADX` field mul+square
//! with the branch-free Solinas fold, and the GLV+wNAF variable-base +
//! double-base public multiplies. The core-vs-portable differentials in
//! `oracle_test.zig` are live. See `gate.zig`, `fast_core.zig`, `SPEC.md`.
//!
//! `sign.zig` supplies BIP340 Schnorr sign/verify and plain ECDSA verify;
//! `ecdsa_recover.zig` supplies the two ECDSA operations that layer doesn't
//! (RFC 6979 deterministic sign + public-key recovery from a compact
//! recoverable signature) — moved in from `lninvoice` (the original, and
//! for a while only, consumer) once it became clear the functionality is
//! general secp256k1 machinery rather than anything BOLT#11-specific.

const std = @import("std");

pub const field = @import("field.zig");
pub const group = @import("group.zig");
pub const scalar = @import("scalar.zig");
pub const sign = @import("sign.zig");
pub const ecdsa_recover = @import("ecdsa_recover.zig");
pub const gate = @import("gate.zig");
pub const fast_core = @import("fast_core.zig");

/// The secp256k1 base field element (over `p = 2^256 − 2^32 − 977`).
pub const Fe = field.Fe;
/// A secp256k1 curve point.
pub const Secp256k1 = group.Secp256k1;
/// A point in affine coordinates.
pub const AffineCoordinates = group.AffineCoordinates;
/// A scalar-field element (mod the group order `n`).
pub const Scalar = scalar.Scalar;

/// True iff the field multiply/square hot path is running on the gated amd64
/// `MULX/ADX` core rather than the portable Solinas reduction (true on any
/// x86-64 build with the ADX + BMI2 target features).
pub const field_asm_active = field.field_asm_active;

pub const meta = .{
    .platform = .any, // portable Solinas everywhere; amd64 MULX/ADX is an accel path
    .role = .util, // pure computation — no I/O
    .concurrency = .reentrant, // no globals; all values are plain types
    .model_after = "libsecp256k1 (special-prime reduction + GLV endomorphism + MULX/ADX field asm); std.crypto.ecc.Secp256k1 as the byte-exact correctness oracle",
    .deps = .{}, // std only
};

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    _ = field;
    _ = group;
    _ = scalar;
    _ = sign;
    _ = ecdsa_recover;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("oracle_test.zig");
    _ = @import("bench.zig");
}

test "meta.model_after names libsecp256k1 and the std oracle" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "libsecp256k1") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Secp256k1") != null);
}
