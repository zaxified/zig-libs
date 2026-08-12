// SPDX-License-Identifier: MIT

//! bfv — leveled BFV homomorphic encryption over `Z_q[X]/(X^N+1)`, in RNS.
//!
//! **Fully Homomorphic Encryption, Part 1 (arithmetic backbone + scheme
//! scaffold).** FHE lets you compute on ciphertexts: `Dec(f(Enc(x))) = f(x)`.
//! BFV (Fan-Vercauteren 2012) is the cleanest EXACT-integer scheme — no
//! CKKS-style approximate rescaling — and matches Microsoft SEAL's default
//! parameter/NTT design, which makes it cross-checkable **in principle**
//! (small fix-space, deterministic construction). No SEAL vectors have
//! actually been produced or checked in, though (`modules/bfv/data/` is
//! empty) — what validates the scheme layer today is `Dec(Enc(x)) == x` and
//! the homomorphic property against this module's own reference helpers, not
//! against SEAL. This module targets a *leveled* BFV that can homomorphically
//! ADD and MULTIPLY to a bounded depth (no bootstrapping).
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
//! The **scheme layer (`bfv.Bfv`) is complete**: the `SecretKey`/`PublicKey`/
//! `RelinKey`/`Ciphertext` types and the (non-noise-sensitive) homomorphic
//! `add`/`sub` are real; `keyGen`/`encrypt`/`decrypt` landed as
//! `scheme_core_implemented` (Part 2, Opus — SEAL-KAT-**able**, meaning the
//! construction is the kind an external byte-exact KAT could validate, NOT
//! that a SEAL KAT has actually been run — see "Verification" below and
//! `gate.zig`) and `mul`/`relinearize`/`noiseBudget` as
//! `fable_core_implemented` (Part 3, the genuine-Fable noise-management
//! core). See `gate.zig`, `SPEC.md`. (Byte codecs for the key/ciphertext
//! types are a deferred backlog item.)
//!
//! ## Verification (what actually backs "complete")
//! `keyGen`/`encrypt`/`decrypt`/`add` are checked by `Dec(Enc(x)) == x` and
//! `Dec(Enc(a) + Enc(b)) == a+b (mod t)` against this module's own
//! `encode.addRef` reference — never against Microsoft SEAL. `mul`/
//! `relinearize` are checked the same way against `encode.mulRef`, plus the
//! worst-case noise-ledger argument in SPEC.md. No SEAL output, KAT vector,
//! or transcript exists anywhere in this repo for bfv.
//!
//! ## Parameters
//! `params.test_tiny` / `test_mul` / `bfv_toy` are correctness-only toy sets
//! and claim no security level. `params.sec_n8192_logq218` (`N = 8192`,
//! `log2 q = 218`, `t = 65537`) is the security-grade set — the shape the
//! HomomorphicEncryption.org tables give for ~128-bit classical security with a
//! ternary secret. Correctness at those parameters is tested end to end (a
//! depth-2 evaluation decrypts exactly; the worst-case ledger in `params.zig`
//! guarantees depth 4); the 128-bit figure is a citation of those tables, not a
//! lattice estimate run here, and nothing about deployment hardening (byte
//! codecs, side channels beyond `SPEC.md`'s stated boundary) is claimed.
//!
//! ## Randomness
//!
//! `keyGen`, `encrypt` and `genRelinKey` take `io: std.Io` and draw through
//! `entropy.SecureSource`, the fail-closed `std.Random` adapter over
//! `std.Io.randomSecure` (`modules/entropy`) — not the silently-degrading
//! `std.Io.random` a bare `std.Random.IoSource` would bind. A bare
//! `std.Random` parameter would let a consumer pass `DefaultPrng.init(0)` at
//! a call site that looks identical to a correct one — and here that is not
//! a weakening but a break: with `u,e0,e1` predictable, `c0 − p0·u − e0 = Δ·m`
//! recovers the plaintext **without the secret key**. The `…ForTest` twins
//! keep `std.Random` so the KATs stay reproducible; see `bfv.zig`'s
//! "Randomness" doc comment for the fuller picture, including why failing
//! closed via `std.Io.randomSecure` is settled policy now, not an open
//! question (`CONVENTIONS.md` §2.2, formerly tracked as B7).
//!
//! Deferred increments: bootstrapping, CKKS (approximate), key rotation /
//! Galois automorphisms (batching rotations), full CRT-slot SIMD encoding,
//! byte codecs.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure computation; the entropy seam is entropy.SecureSource over a portable std.Io, no raw getrandom(2)
    .role = .util,
    .concurrency = .reentrant, // no shared state; caller supplies all inputs
    .model_after = "Fan-Vercauteren BFV (ePrint 2012/144) + Microsoft SEAL RNS/NTT design",
    .deps = .{"entropy"}, // fail-closed secret draws in keyGen/encrypt/genRelinKey (entropy.SecureSource)
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
    _ = @import("bench.zig"); // opt-in via BFV_BENCH; SKIPs otherwise
}

test "meta.model_after names BFV + Fan-Vercauteren" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BFV") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Fan-Vercauteren") != null);
}
