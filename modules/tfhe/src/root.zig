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
//! The parameter sets, key/ciphertext layouts and the gate encoding are
//! tfhe-rs 1.8.1's boolean layer (`params.tfhers_default` = its
//! `DEFAULT_PARAMETERS`); `interop_test.zig` holds this module to tfhe-rs in
//! both directions — key switching and the bootstrap byte-identical, gates
//! evaluated across implementations. `boolean.zig` is the consumer-facing
//! layer (`ClientKey`, `ServerKey`, gates), `codec.zig` the byte encodings.
//! `toy` remains for fast tests and claims no security; for the tfhe-rs sets
//! the security level is tfhe-rs's sizing (see `SPEC.md`).
//!
//! ## Randomness
//!
//! Key generation and encryption take `io: std.Io` and draw through
//! `entropy.SecureSource`, the fail-closed `std.Random` adapter over
//! `std.Io.randomSecure` (`modules/entropy`). A bare `std.Random` parameter
//! would let a consumer pass `DefaultPrng.init(0)` at a call site that looks
//! identical to a correct one, and a predictable stream does not weaken this
//! scheme — it removes it (`dim` ciphertexts then recover the secret key by
//! Gaussian elimination). The `…ForTest` twins keep `std.Random` for the KATs
//! and seeded end-to-end tests; see `tfhe.zig`'s "Randomness" doc comment
//! (`CONVENTIONS.md` §2.2).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "TFHE gate bootstrapping — unbounded-depth FHE on encrypted bits: binary gates, programmable bootstrap, tfhe-rs's boolean parameter sets and key/ciphertext layouts (interoperates with tfhe-rs 1.8.1 both ways).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
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
/// Constant-time Gaussian error sampling (Box–Muller without branches).
pub const noise = @import("noise.zig");
pub const params = @import("params.zig");

// Scheme layer.
pub const gate = @import("gate.zig");
/// Encrypted bits and binary gates (tfhe-rs's boolean encoding).
pub const boolean = @import("boolean.zig");
/// Byte encodings of keys and ciphertexts (tfhe-rs's container order).
pub const codec = @import("codec.zig");
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
    _ = noise;
    _ = params;
    _ = tfhe_mod;
    _ = boolean;
    _ = codec;
    _ = @import("harness_test.zig");
    _ = @import("interop_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("bench.zig");
}

test "meta.model_after names TFHE + FHEW" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "TFHE") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "FHEW") != null);
}
