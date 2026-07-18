// SPDX-License-Identifier: MIT

//! tfhe — TFHE/FHEW-style programmable **gate bootstrapping**: unbounded-depth
//! FHE via blind rotation.
//!
//! The sibling `bfv` module is *leveled* FHE — it can add and multiply to a
//! bounded depth before noise exhausts the budget. **Bootstrapping** is what
//! removes the bound: after every gate, a blind rotation homomorphically
//! re-decodes the message through a programmable LUT and emits a FRESH,
//! low-noise ciphertext, so an arbitrarily deep circuit stays correct. This
//! module implements the TFHE/FHEW line (Chillotti–Gama–Georgieva–Izabachène;
//! Ducas–Micciancio) rather than BFV/BGV digit-extraction bootstrapping: it is
//! self-contained (LWE/GLWE/GGSW over the power-of-two torus `Z_{2^32}`, a
//! negacyclic ring, no pairing, no external C) and is the canonical
//! bootstrapping demonstration.
//!
//! ## Scaffold status (this commit)
//! The whole **mechanical layer is REAL and tested** — the negacyclic ring
//! (`poly`), the signed gadget decomposition (`gadget`), torus (de)coding and
//! modulus switching (`torus`), plus `tfhe.Tfhe`'s LWE/GLWE/GGSW keygen/encrypt/
//! decrypt, bootstrap-key + key-switch-key generation, sample extraction, LWE
//! key switching, and the cleartext LUT+rotation oracle (`clearBootstrap`).
//!
//! The **irreducible soundness core is GATED** behind `gate.fable_core_implemented`
//! (`@panic("TODO(fable/core)")`): `externalProduct`, `cmux`, `blindRotate`,
//! `bootstrap`. There is no external byte-exact KAT for these, so the harness
//! defends with a cleartext oracle, deliberately-broken positive controls that
//! pass today, and (once the core lands) an unlimited-depth bootstrap chain.
//! See `SPEC.md` for the Fable boundary and the failure-probability ledger.
//!
//! **Toy/test parameters only — no security level is claimed.**

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure computation; caller-supplied std.Random (no OS RNG)
    .role = .util,
    .concurrency = .reentrant, // no shared state; caller supplies all inputs
    .model_after = "TFHE (Chillotti–Gama–Georgieva–Izabachène, ePrint 2016/870) + FHEW (Ducas–Micciancio, EUROCRYPT 2015)",
    .deps = .{}, // std-only
};

// Mechanical backbone (all REAL, ungated).
pub const torus = @import("torus.zig");
pub const poly = @import("poly.zig");
pub const gadget = @import("gadget.zig");
pub const params = @import("params.zig");

// Scheme layer (types + mechanical ops real; the four cores gated).
pub const gate = @import("gate.zig");
const tfhe_mod = @import("tfhe.zig");
/// `Tfhe(P)` — a TFHE instance for a compile-time parameter set. See `tfhe.zig`.
pub const Tfhe = tfhe_mod.Tfhe;

// Convenience re-exports.
pub const Params = params.Params;
pub const Poly = poly.Poly;
pub const Torus = torus.Torus;

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    std.testing.refAllDecls(@This());
    _ = torus;
    _ = poly;
    _ = gadget;
    _ = params;
    _ = tfhe_mod;
    _ = @import("harness_test.zig");
}

test "meta.model_after names TFHE + FHEW" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "TFHE") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "FHEW") != null);
}
