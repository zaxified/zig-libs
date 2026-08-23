// SPDX-License-Identifier: MIT

//! decaf448 — the decaf448 prime-order group (RFC 9496, "The ristretto255
//! and decaf448 Groups", §5), built on `ed448`'s edwards448 curve
//! arithmetic. Sibling to `std.crypto.ecc.Ristretto255` one curve family
//! up: where ristretto255 wraps Curve25519 to eliminate its cofactor-8
//! pitfalls, decaf448 wraps edwards448 to eliminate its cofactor-4
//! pitfalls, giving protocols built on `ed448` (threshold signing, VRFs,
//! anonymous credentials, any construction that assumes a clean
//! prime-order group — see RFC 9496 §1's own motivation, "the octuple-spend
//! vulnerability" class of bug) the SAME abstraction std ships natively for
//! Curve25519 but does not for the 448-bit family.
//!
//! **Closes `ed448`'s own out-of-scope flag.** `ed448/src/root.zig`'s
//! module doc comment names decaf448 explicitly: "Deferred (explicitly out
//! of scope for this scaffold — see SPEC.md): decaf448 (the prime-order-
//! group wrapper eliminating edwards448's cofactor-4 entirely)". This
//! module is that deferred work.
//!
//! **Status: COMPLETE.** The group-element type (`element.Element`), every
//! MECHANICAL group operation (`add`/`sub`/`negate`/`scalarMul`/`equals`,
//! `identity`/`generator`), the 56-byte scalar wire-width bridge to
//! `ed448.scalar` (`scalar.zig`), the RFC 9496 §5.1 implementation
//! constants (with independent self-checks), and an airtight byte-exact
//! KAT harness against the OFFICIAL RFC 9496 Appendix B decaf448 test
//! vectors (`kat_vectors.zig`/`kat_test.zig`) are all real. The four
//! IRREDUCIBLE decaf-specific field-math cores — `element.sqrtRatioM1`
//! (RFC 9496 §5.2), `Element.encode` (§5.3.2), `Element.decode` (§5.3.1),
//! and the inner `MAP` primitive backing `oneWayMap` (§5.3.4) — are now
//! implemented and `gate.core_implemented` is `true`, so every KAT test
//! runs (all pass, byte-exact against RFC 9496 Appendix B in both Debug
//! and ReleaseFast); see `gate.zig`'s own doc comment for the real/gated
//! split and `element.zig` for each core's full doc-commented contract.
//!
//! Zig std GAP: yes — `std.crypto.ecc.Ristretto255` exists for Curve25519;
//! std has no decaf448/edwards448 prime-order-group counterpart at all
//! (matching `ed448`'s own "no 448-bit curve of any kind" gap one layer
//! down). `std.crypto.ecc.Ristretto255` is this module's best STRUCTURAL
//! reference (see `element.zig`'s Provenance note) — no source copied.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "decaf448 prime-order group (RFC 9496) over `ed448` — eliminates cofactor-4 pitfalls for threshold signing, VRFs, anonymous credentials.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "RFC 9496 (\"The ristretto255 and decaf448 Groups\") §5 — decaf448 specifically; std.crypto.ecc.Ristretto255 consulted as the structural reference for the sibling ristretto255 construction one curve family down (API shape only, no source copied — decaf448's own constants/curve/simpler p≡3(mod4) SQRT_RATIO_M1 all differ)",
    .deps = .{"ed448"},
};

pub const gate = @import("gate.zig");
pub const scalar = @import("scalar.zig");
pub const element = @import("element.zig");

pub const Element = element.Element;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = gate;
    _ = scalar;
    _ = element;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta names RFC 9496 and its deps include ed448" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "9496") != null);
    try std.testing.expectEqualStrings("ed448", meta.deps[0]);
}

test "core_implemented gate resolves to a bool" {
    const v: bool = gate.core_implemented;
    _ = v;
}
