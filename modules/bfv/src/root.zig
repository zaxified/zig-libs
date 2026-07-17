// SPDX-License-Identifier: MIT

//! bfv — leveled BFV homomorphic encryption over `Z_q[X]/(X^N+1)`, in RNS.
//!
//! **Fully Homomorphic Encryption, Part 1 (arithmetic backbone + scheme
//! scaffold).** FHE lets you compute on ciphertexts: `Dec(f(Enc(x))) = f(x)`.
//! BFV (Fan-Vercauteren 2012) is the cleanest EXACT-integer scheme — no
//! CKKS-style approximate rescaling — and matches Microsoft SEAL's default, so
//! it is cross-checkable. This module targets a *leveled* BFV that can
//! homomorphically ADD and MULTIPLY to a bounded depth (no bootstrapping).
//!
//! ## Part-1 status (this commit)
//! The whole **arithmetic backbone is REAL and byte-exact-KAT'd** — the piece
//! FHE is actually built on:
//!   - `modarith` — word-size modular arithmetic over an NTT prime `q<2^62`.
//!   - `ntt` — the negacyclic Number-Theoretic Transform (Cooley-Tukey /
//!     Gentleman-Sande), O(N log N) polynomial multiply mod `X^N+1`. Anchored
//!     byte-exact vs an independent Python re-derivation AND vs an independent
//!     schoolbook negacyclic convolution.
//!   - `rns` — Residue Number System / CRT over an NTT-prime chain for the
//!     large ciphertext modulus, with exact base conversion.
//!   - `ring` — `RnsPoly`, the RLWE ring `R_q` (add / negate / NTT / pointwise
//!     multiply) the scheme is built from.
//!   - `encode` — BFV plaintext (`R_t`) coefficient + integer encodings, and
//!     the `addRef`/`mulRef` plaintext-space references the homomorphic
//!     anchors decrypt against.
//!   - `params` — parameter sets + NTT-friendly-prime validation.
//!
//! The **scheme layer (`bfv.Bfv`) is scaffolded**: types, byte codecs, and the
//! (non-noise-sensitive) homomorphic `add`/`sub` are real; `keyGen`/`encrypt`/
//! `decrypt` are gated `scheme_core_implemented` (Part 2, Opus — SEAL-KAT-able)
//! and `mul`/`relinearize`/`noiseBudget` are gated `fable_core_implemented`
//! (Part 3, the genuine-Fable noise-management core). See `gate.zig`, `SPEC.md`.
//!
//! Deferred increments: bootstrapping, CKKS (approximate), key rotation /
//! Galois automorphisms (batching rotations), full CRT-slot SIMD encoding,
//! security-grade parameter sets. **No security level is claimed in Part 1.**

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure computation; caller-supplied std.Random (no OS RNG)
    .role = .util,
    .concurrency = .reentrant, // no shared state; caller supplies all inputs
    .model_after = "Fan-Vercauteren BFV (ePrint 2012/144) + Microsoft SEAL RNS/NTT design",
    .deps = .{}, // std-only
};

// Arithmetic backbone (all REAL, ungated).
pub const modarith = @import("modarith.zig");
pub const ntt = @import("ntt.zig");
pub const rns = @import("rns.zig");
pub const ring = @import("ring.zig");
pub const encode = @import("encode.zig");
pub const params = @import("params.zig");

// Scheme layer (types real; cores gated).
pub const gate = @import("gate.zig");
const bfv_mod = @import("bfv.zig");
/// `Bfv(P)` — a BFV instance for a compile-time parameter set. See `bfv.zig`.
pub const Bfv = bfv_mod.Bfv;

pub const kat_vectors = @import("kat_vectors.zig");

// Convenience re-exports.
pub const Ntt = ntt.Ntt;
pub const RnsPoly = ring.RnsPoly;
pub const Plaintext = encode.Plaintext;
pub const Params = params.Params;

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    std.testing.refAllDecls(@This());
    _ = modarith;
    _ = ntt;
    _ = rns;
    _ = ring;
    _ = encode;
    _ = params;
    _ = bfv_mod;
    _ = kat_vectors;
    _ = @import("kat_test.zig");
}

test "meta.model_after names BFV + Fan-Vercauteren" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BFV") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Fan-Vercauteren") != null);
}
