// SPDX-License-Identifier: MIT
//! ed448 — Ed448 (EdDSA over edwards448, RFC 8032 §5.2) and X448 (the
//! Montgomery-form curve448 Diffie-Hellman function, RFC 7748 §4.2/§5),
//! the "Goldilocks" 448-bit curve family: a full new curve/field family
//! `std.crypto` does not have (std ships `Edwards25519`/`Curve25519` and
//! the NIST P-curves/secp256k1, but no 448-bit curve of any kind).
//! Consumers: applications, CAs, or TLS stacks that need the ~224-bit
//! security level / 448-bit curve — RFC 8032 and RFC 7748 both
//! standardize it as the sibling to Ed25519/X25519 one security level up.
//!
//! **Status: implemented.** Every byte-level/wire concern (field/scalar/
//! point/signature encoding, RFC-mandated clamping, the SHAKE256 `dom4`
//! domain-separation framing, the sign/verify orchestration) AND every
//! number-theory concern (`Fp448` field arithmetic with its Goldilocks/
//! Solinas reduction; the RFC 7748 Montgomery ladder; edwards448 point
//! add/double/scalar-multiply; the mod-`L` scalar arithmetic EdDSA
//! signing needs) is real and constant-time on the secret-input paths —
//! see `field.zig`/`x448.zig`/`ed448.zig`/`scalar.zig`'s own module doc
//! comments for the per-file breakdown and `SPEC.md`'s threat model for
//! the constant-time posture. `kat_test.zig` validates the whole stack
//! byte-exact against the official RFC 7748 §5.2/§6.2 (X448) and RFC
//! 8032 §7.4/§7.5 (Ed448/Ed448ph) test vectors.
//!
//! Zig std GAP: yes — see the module-level doc comments in `field.zig`
//! (base field), `x448.zig` (Montgomery DH), and `ed448.zig` (EdDSA) for
//! the specific `std.crypto.ecc`/`std.crypto.sign`/`std.crypto.dh`
//! counterpart each one's shape is modeled after, one curve family up
//! from 25519.
//!
//! Deferred (explicitly out of scope for this scaffold — see `SPEC.md`):
//! **decaf448** (the prime-order-group wrapper eliminating edwards448's
//! cofactor-4 entirely) and any hash-to-curve / Elligator2 map for
//! edwards448 (RFC 9380 defines one; neither RFC 7748 nor RFC 8032
//! themselves require it for plain X448/Ed448 DH and signing).

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "RFC 7748 (X448) + RFC 8032 §5.2 (Ed448/Ed448ph) — the Goldilocks/curve448 family; API shape mirrors std.crypto.ecc.Curve25519/Edwards25519 + std.crypto.dh.X25519 + std.crypto.sign.Ed25519 one curve family up (std has no 448-bit curve of its own)",
    .deps = .{},
};

pub const field = @import("field.zig");
pub const x448 = @import("x448.zig");
pub const ed448 = @import("ed448.zig");
pub const scalar = @import("scalar.zig");

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = field;
    _ = x448;
    _ = ed448;
    _ = scalar;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta names both RFC 7748 and RFC 8032" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "7748") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "8032") != null);
}
