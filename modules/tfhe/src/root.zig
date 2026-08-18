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
//! ## Status: the gated Fable core is IMPLEMENTED (`gate.fable_core_implemented
//! = true`) — no `@panic` remains in this module; all tests pass, no skips.
//! The mechanical layer — the negacyclic ring (`poly`), the signed gadget
//! decomposition (`gadget`), torus (de)coding and modulus switching (`torus`),
//! plus `tfhe.Tfhe`'s LWE/GLWE/GGSW keygen/encrypt/decrypt, bootstrap-key +
//! key-switch-key generation, sample extraction, LWE key switching, and the
//! cleartext LUT+rotation oracle (`clearBootstrap`) — was always real and
//! tested. The **irreducible soundness core** — `externalProduct`, `cmux`,
//! `blindRotate`, `bootstrap` — is now real too: the once-gated
//! `@panic("TODO(fable/core)")` stubs are gone, and the previously
//! SKIP-gated end-to-end anchors (programmable gate, 2-input AND,
//! unlimited-depth bootstrap chain, corrupted-bootstrap-key control, noise
//! budget) all run and pass. There is still no external byte-exact KAT for
//! these four functions, so verification leans on the cleartext oracle, the
//! deliberately-broken positive controls, and the unlimited-depth chain
//! property instead — see `SPEC.md` for the full verification-level
//! breakdown and the failure-probability ledger.
//!
//! **Toy/test parameters only — no security level is claimed.**
//!
//! ## Randomness
//!
//! Key generation and encryption take `io: std.Io` and draw through
//! `entropy.SecureSource`, the fail-closed `std.Random` adapter over
//! `std.Io.randomSecure` (`modules/entropy`) — not the silently-degrading
//! `std.Io.random` a bare `std.Random.IoSource` would bind. A bare
//! `std.Random` parameter would still be worse — it would let a consumer
//! pass `DefaultPrng.init(0)` at a call site that looks identical to a
//! correct one, and a predictable stream does not weaken this scheme — it
//! removes it (`dim` ciphertexts then recover the secret key by Gaussian
//! elimination). The `…ForTest` twins keep `std.Random` for the KATs and
//! seeded end-to-end tests; see `tfhe.zig`'s "Randomness" doc comment for
//! the fuller picture, including why failing closed via
//! `std.Io.randomSecure` is settled policy now, not an open question
//! (`CONVENTIONS.md` §2.2, formerly tracked as B7).

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure computation; the entropy seam is entropy.SecureSource over a portable std.Io, no raw getrandom(2)
    .role = .util,
    .concurrency = .reentrant, // no shared state; caller supplies all inputs
    .model_after = "TFHE (Chillotti–Gama–Georgieva–Izabachène, ePrint 2016/870) + FHEW (Ducas–Micciancio, EUROCRYPT 2015)",
    .deps = .{"entropy"}, // fail-closed secret draws in every keyGen/encrypt entry point (entropy.SecureSource)
};

// Mechanical backbone (all REAL, ungated).
pub const torus = @import("torus.zig");
pub const poly = @import("poly.zig");
/// Exact `O(N log N)` negacyclic ring multiply (integer NTT, no FFT, no
/// rounding budget) — the engine behind `poly.Poly(N).mul` for large `N`.
pub const ntt = @import("ntt.zig");
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
    _ = ntt;
    _ = gadget;
    _ = params;
    _ = tfhe_mod;
    _ = @import("harness_test.zig");
    _ = @import("bench.zig");
}

test "meta.model_after names TFHE + FHEW" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "TFHE") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "FHEW") != null);
}
