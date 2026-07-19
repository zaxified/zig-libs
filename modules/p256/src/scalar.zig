// SPDX-License-Identifier: MIT

//! scalar — the NIST P-256 scalar field (arithmetic mod the group order
//! `n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`).
//!
//! ## Scope / dedup: the scalar field is re-exported from std, on purpose
//!
//! p256's reason to exist is the *field* and *group* arithmetic hot path (the
//! ~hundreds of base-field multiplies per scalar multiply), which it accelerates
//! with the P-256 special-prime reduction + `MULX/ADX` core + windowed/comb
//! scalar multiplies. Scalar-field arithmetic mod `n` is a negligible slice of
//! an ECDSA operation (a handful of `mul`/`add`/`invert` mod `n` per signature
//! vs. the point multiply's field-op storm), and `n` has no exploitable special
//! form — so accelerating it would be effort with no measurable payoff. p256
//! therefore re-exports std's constant-time scalar field verbatim and spends its
//! complexity budget where the cost is. This is a deliberate scope decision,
//! documented in `SPEC.md`.
//!
//! ## No GLV here — P-256 has no efficiently-computable endomorphism
//!
//! Unlike secp256k1 (k256), P-256 admits no `φ(x, y) = (β·x, y)` acting as `·λ`,
//! so there is no balanced-lattice `splitScalar` to decompose a scalar and no
//! half-length combine. Variable-base multiplies are plain windowed forms
//! (wNAF/`slide` for public verify, constant-time windowed for secret), and the
//! signing `k·G` uses a fixed-base comb — see `group.zig`.

const std = @import("std");

/// The NIST P-256 scalar field, re-exported from std (see the scope note above).
pub const scalar = std.crypto.ecc.P256.scalar;
pub const Scalar = scalar.Scalar;
pub const CompressedScalar = scalar.CompressedScalar;

/// The scalar field (group) order `n`.
pub const field_order: u256 = scalar.field_order;

test "scalar order matches std.crypto.ecc.P256.scalar.field_order" {
    try std.testing.expectEqual(std.crypto.ecc.P256.scalar.field_order, field_order);
    // n < p (the two moduli are distinct — a common P-256 footgun).
    try std.testing.expect(field_order != @import("field.zig").field_order);
}
