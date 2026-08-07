// SPDX-License-Identifier: MIT

//! rescue — **the other arithmetization-oriented hash**: same goal as
//! `poseidon` (be cheap inside an arithmetic circuit), opposite trade.
//!
//!
//! **Zeroization: none, deliberately (CONVENTIONS §2.1 Z3).** The chaining
//! state and the message-block buffer are the internal working state of a
//! transform, not a secret this module owns — they are Z3, the class the repo
//! settled once so it stops being re-raised module by module. `std` takes the
//! same position: `sha2`, `sha3`, `blake2`, `blake3`, `hmac` and `hkdf` contain
//! no `secureZero` at all (`hmac` holds a real MAC key in `o_key_pad` and still
//! does not wipe it), while `keccak_p`/`ascon` expose an opt-in `secureZero()`
//! their own hash paths never call. The technical reason is in §2.1: the
//! compression function keeps these words in registers and spill slots for its
//! whole run, and no `secureZero` reaches those, so wiping the struct clears
//! the copy least likely to be the one that leaks. A caller with a concrete
//! reason to want the state cleared should say so and get an opt-in
//! `secureZero()` here — that is a feature request, not a defect report.
//! Poseidon uses one S-box, `x^5`, in every round. Rescue alternates `x^alpha`
//! with its **inverse** `x^(1/alpha)`: one half-round raises to the 7th power,
//! the next takes a 7th root. The root is an exponentiation by a full 64-bit
//! exponent — 72 multiplications against the forward S-box's 5 — so the
//! inverse half-rounds are **76% of the permutation's software cost**
//! (measured), work no Poseidon round does at all. In exchange, a *verifier*
//! never computes the root:
//! it checks `y^7 == x`, which is the same degree-7 constraint as the forward
//! direction. Rescue buys a shorter, more uniform algebraic description
//! (7 rounds, all identical) with software cost that a prover happily pays and
//! a plain hasher does not.
//!
//! `README.md` has the "which one should I reach for" table.
//!
//! ## What is implemented
//!
//!   - **Rescue-Prime Optimized (RPO)** — eprint 2022/1577 — over the
//!     Goldilocks field `p = 2^64 - 2^32 + 1`, at both published instances:
//!     `m = 12` (128-bit, 4-element digest) and `m = 16` (160-bit, 5-element).
//!     This is the variant deployed systems actually run.
//!   - **Both sponge framings that exist for it**: the specification's own
//!     (`spec128` / `spec160`) and miden-crypto's `Rpo256`, which is what the
//!     Miden VM's Merkle roots and account commitments are made of. They are
//!     different hashes over the same permutation — see `rpo.zig`.
//!   - **Rescue-XLIX** (`xlix`) — the *original* Rescue-Prime round order from
//!     eprint 2020/1143, permutation only, so the RPO-vs-paper divergence is
//!     executable rather than merely documented.
//!   - The Goldilocks field itself (`goldilocks`), ~240 lines, private to this
//!     module by design: RPO is specified over this prime and no field module
//!     in this repo is 64-bit. Not a general-purpose field.
//!
//! ## Anchoring
//!
//! **Grade 1 — 57 published known-answer vectors, byte-exact.** 19 from the
//! RPO report's 128-bit instance, 19 from its 160-bit instance, 19 from
//! miden-crypto's own Rust test suite, plus Winterfell's published Rescue-XLIX
//! permutation KAT. Round constants are **derived** from SHAKE256 exactly as
//! the authors' sage does and separately pinned element-by-element against the
//! tables miden-crypto embeds. Every vector was extracted from its upstream
//! file by script, with the command and the file's SHA-256 recorded in
//! `upstream_vectors.zig`.
//!
//! ## Entry points
//!
//! ```zig
//! const rescue = @import("rescue");
//!
//! // Miden-compatible (this is almost certainly the one you want)
//! const d  = rescue.Rpo256.hashElements(&.{ 1, 2, 3 });
//! const b  = rescue.Rpo256.digestToBytes(d);          // 32 bytes
//! const nd = rescue.Rpo256.merge(left, right);        // Merkle node
//!
//! // The specification's own sponge
//! const s  = try rescue.spec128.hash(&.{ 1, 2, 3 });  // 4 elements (empty input is refused)
//! const s5 = try rescue.spec160.hash(&.{ 1, 2, 3 });  // 5 elements
//!
//! // The bare permutation
//! var st: rescue.Rpo256.State = .{0} ** 12;
//! rescue.Rpo256.permute(&st);
//! ```
//!
//! ## Not here
//!
//! Circuit/constraint-system integration; RPX (`eprint 2023/1045`, the
//! Rescue-Prime eXtended variant Miden also ships); a sponge for `xlix`;
//! Rescue over `bn254`/`bls12_381`. `SPEC.md` says why for each.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure 64-bit integer arithmetic — no OS, no libc, no entropy
    .role = .util, // a hash function; no I/O, no wire format of its own
    .concurrency = .reentrant, // every entry point is a pure function of its arguments
    .model_after = "the RPO authors' rescue_prime_optimized.sage reference, miden-crypto's Rpo256, and Winterfell's Rp64_256",
    .deps = .{}, // std only — the Goldilocks field lives inside this module
};

// ── public API ──────────────────────────────────────────────────────────────

/// The Goldilocks field `p = 2^64 - 2^32 + 1`, with the two S-box exponents.
/// Exposed because callers hold field elements, not bytes.
pub const goldilocks = @import("goldilocks.zig");

/// A field element — a `u64` that is always canonical (`< p`).
pub const Fe = goldilocks.Fe;

/// Reduce an arbitrary `u64` into the field.
pub const fromU64 = goldilocks.fromU64;

/// The parameter generator: seed string, SHAKE256 round constants, MDS rows.
/// Exposed because "where do these numbers come from" is the whole question
/// with an AO hash, and the answer should be readable and testable.
pub const params = @import("params.zig");

/// The RPO permutation, parameterised by instance.
pub const Permutation = @import("perm.zig").Permutation;

/// The specification's own sponge, 128-bit instance (`m = 12`, 4-element digest).
pub const spec128 = @import("rpo.zig").spec128;

/// The specification's own sponge, 160-bit instance (`m = 16`, 5-element digest).
pub const spec160 = @import("rpo.zig").spec160;

/// miden-crypto's `Rpo256` — the deployed framing.
pub const Rpo256 = @import("rpo.zig").Rpo256;

/// Rescue-XLIX: the original Rescue-Prime round order (permutation only).
pub const xlix = @import("xlix.zig");

test {
    _ = goldilocks;
    _ = params;
    _ = @import("perm.zig");
    _ = @import("rpo.zig");
    _ = xlix;
    _ = @import("vectors_test.zig");
    _ = @import("constants_test.zig");
    _ = @import("fuzz_test.zig");
}

test "meta.deps is empty because the field is deliberately in-module" {
    // Rescue-Prime Optimized is specified over Goldilocks and nothing else.
    // The repo's `bn254`/`bls12_381` scalar fields are 254/255-bit and cannot
    // host it, and a 64-bit field with exactly one consumer does not earn a
    // module — so `goldilocks.zig` lives here and this list stays empty. If a
    // second consumer ever appears, that is the moment to extract it.
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
}
