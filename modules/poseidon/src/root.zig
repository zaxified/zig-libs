// SPDX-License-Identifier: MIT

//! poseidon — **the ZK-friendly hash**: a permutation built from field
//! additions, multiplications and one `x^5` S-box, so that hashing *inside*
//! an arithmetic circuit costs a few hundred constraints instead of the tens
//! of thousands SHA-256 costs (SHA-256 is cheap on bits and this repo's
//! circuits are not made of bits).
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
//! This is the hash that Merkle trees, commitments and Fiat-Shamir
//! transcripts in the sibling `groth16` / `bn254` / `bulletproofs` world are
//! actually made of.
//!
//! ## What is implemented
//!
//!   - The **HADES permutation** — `R_F/2` full rounds, `R_P` partial rounds,
//!     `R_F/2` full rounds; every round is add-round-constants → S-box → MDS
//!     multiply (`perm.zig`).
//!   - The **Grain LFSR parameter generator** that produces the round
//!     constants and the MDS matrix, ported from the Poseidon authors'
//!     reference sage script (`grain.zig`). It runs once per instance, in
//!     `Perm(t).init()` — see `grain.derive` for why that is at run time and
//!     not at comptime.
//!   - The **MDS subspace-trail security checks** the reference generator
//!     runs on each candidate matrix — `algorithm_1`/`2`/`3` and
//!     `check_minpoly_condition` (`mds_security.zig`) — and the rejection
//!     loop around them. A rejection consumes more Grain bits, so leaving
//!     them out would silently produce the wrong parameters for any set where
//!     upstream rejected a candidate. None of the 18 sets shipped here does,
//!     which is why the tables are unchanged.
//!   - Two field instantiations:
//!     - `bn254` — circomlib's parameter set, `t = 2..17` (1..16 inputs),
//!       which is what deployed circom circuits use;
//!     - `bls12_381` — the authors' `poseidonperm_x5_255_{3,5}`, `t = 3, 5`.
//!
//! ## Anchoring
//!
//! **Grade 1 — published external vectors, byte-exact.** The permutation is
//! pinned against the Poseidon authors' own `test_vectors.txt` (all four
//! GF(p) cases) and against circomlib's known-answer values plus a full
//! `t = 2..17` sweep taken by *running* circomlibjs; the constants are pinned
//! against circomlib's published constant tables. Provenance — URLs and the
//! exact commands that produced each number — is in `vectors_test.zig` and
//! `constants_test.zig`, not summarised away.
//!
//! ## Entry points
//!
//! An instance carries its derived tables, so build it once:
//!
//! ```zig
//! const p = poseidon.bn254.Perm(3).init();
//! const node = p.compress(left, right);            // Merkle node, Poseidon(2)
//! const h    = p.hash(.{ a, b });                  // same thing, general form
//! const st   = p.hashN(3, initial_state, .{ a, b });// circomlib PoseidonEx
//! const raw  = p.permute(.{ c, a, b });            // the bare permutation
//! ```
//!
//!   - `bn254.Perm(t)` — `t` in 2..17, i.e. `t - 1` inputs.
//!   - `bls12_381.Perm(t)` — `t` in {3, 5}, permutation externally anchored;
//!     the hash framing on this field is not (see that file).
//!
//! ## Not here
//!
//! Variable-length (sponge) hashing, Poseidon2, Rescue/Rescue-Prime, and any
//! circuit/constraint-system integration. `SPEC.md` says why for each, and
//! which of them is the obvious follow-up.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure field arithmetic — no OS, no libc, no entropy source
    .role = .util, // a hash function; no I/O, no wire format of its own
    .concurrency = .reentrant, // instances are immutable after init(); share one freely
    .model_after = "iden3/circomlib + circomlibjs (poseidon.circom, poseidon_reference.js) and the Poseidon authors' hadeshash sage reference",
    .deps = .{ "bn254", "bls12_381" },
};

// ── public API ──────────────────────────────────────────────────────────────

/// The parameter generator. Exposed because "where do these numbers come
/// from" is the whole question with Poseidon, and the answer should be
/// readable and testable rather than a blob.
pub const grain = @import("grain.zig");

/// The subspace-trail security checks a candidate MDS matrix has to pass
/// (`algorithm_1`/`2`/`3` + `check_minpoly_condition` of the reference
/// generator), and the `GF(p)` linear algebra they are built from. Exposed for
/// the same reason `grain` is: the rejection rule is part of "where do these
/// numbers come from", and it should be readable and testable.
pub const mds_security = @import("mds_security.zig");

/// The generic permutation, parameterised by field + round numbers.
pub const Permutation = @import("perm.zig").Permutation;

/// Poseidon over the BN254 scalar field — circomlib's parameter set.
pub const bn254 = @import("bn254_poseidon.zig");

/// Poseidon over the BLS12-381 scalar field — the authors' `x5_255_{3,5}`.
pub const bls12_381 = @import("bls12_381_poseidon.zig");

test {
    _ = grain;
    _ = mds_security;
    _ = @import("linalg.zig");
    _ = bn254;
    _ = bls12_381;
    _ = @import("vectors_test.zig");
    _ = @import("constants_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("rejection_test.zig");
    _ = @import("reference_interop.zig");
    _ = @import("small_field.zig");
}

test "meta.deps names the two scalar fields this builds on" {
    // Both are real: `bn254` carries circomlib's deployed parameter set,
    // `bls12_381` carries the authors' published one. Neither is optional —
    // dropping either would drop a whole grade-1 anchor.
    try std.testing.expectEqual(@as(usize, 2), meta.deps.len);
    try std.testing.expectEqualStrings("bn254", meta.deps[0]);
    try std.testing.expectEqualStrings("bls12_381", meta.deps[1]);
}
