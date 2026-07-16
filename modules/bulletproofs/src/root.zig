// SPDX-License-Identifier: MIT

//! bulletproofs — Bulletproofs zero-knowledge range proofs (Bünz, Bootle,
//! Boneh, Poelstra, Wuille, Maxwell, "Bulletproofs: Short Proofs for
//! Confidential Transactions and More", IEEE S&P 2018) over Ristretto255
//! (`std.crypto.ecc.Ristretto255`): prove a Pedersen-committed value `v`
//! lies in `[0, 2^n)` (`n` typically 64) without revealing `v`, in a proof
//! whose size is LOGARITHMIC in `n` (`~2*log2(n) + 9` group
//! elements/scalars, vs. a naive bit-commitment proof's linear size) —
//! the construction behind Confidential Transactions, Monero-style range
//! proofs, and many zk-rollup circuits.
//!
//! **Status: COMPLETE.** The generators, Pedersen commitment, Fiat-Shamir
//! transcript, proof structs + byte codecs, and the mechanical
//! scalar/vector/multi-scalar-mult helpers are all REAL and tested below.
//! The two genuinely irreducible ZK cores — the Inner-Product Argument
//! (`ipa.zig`'s `proveIpa`/`verifyIpa`) and the range-proof polynomial
//! construction/reduction (`rangeproof.zig`'s `prove`/`verify`) — are
//! implemented (Fable core pass) and exercised by the full
//! property/soundness KAT harness (`gate.core_implemented` is now `true`,
//! so completeness + tamper/cross-commitment/mismatch rejection all run
//! for real). See `gate.zig`.
//!
//! ## Why the IPA is the Fable-hard core
//!
//! Everything else in this module is either (a) ordinary hashing/EC
//! arithmetic with no cryptographic JUDGMENT (`generators.zig`'s NUMS
//! derivation, `transcript.zig`'s Fiat-Shamir chain, `scalarvec.zig`'s
//! inner-product/Hadamard/multi-scalar-mult helpers), or (b) mechanical
//! struct/codec plumbing (`InnerProductProof`/`RangeProof`'s byte
//! encodings). The Inner-Product Argument (`ipa.zig`) is neither: it is a
//! genuine `log2(n)`-round RECURSIVE zero-knowledge protocol whose
//! soundness rests on a special-soundness/rewinding argument over the
//! discrete-log relation problem (Bulletproofs §3 Theorem 1) — getting
//! the per-round fold direction, the challenge-before-fold ordering, and
//! the final multi-exponentiation check exactly right is design work, not
//! transcription. The range-proof's own polynomial construction
//! (`rangeproof.zig`) is the second Fable-hard piece: choosing `l(x)`/
//! `r(x)` so that their inner product simultaneously encodes "`v` is
//! 0/1-decomposable" AND "the decomposition equals `v`" is the paper's
//! own central insight (§4.1), not boilerplate.
//!
//! ## Transcript — module-defined, NOT dalek/Merlin-compatible
//!
//! This module uses a self-contained SHA-512-based Fiat-Shamir transcript
//! (`transcript.zig`), not Merlin (the STROBE-based transcript dalek's
//! `bulletproofs` crate uses). Every Bulletproofs implementation's
//! transcript is implementation-defined (the paper does not pin one
//! down), so a proof from THIS module only verifies against THIS
//! module's own `verify`/`verifyIpa` — it is internally self-consistent
//! (soundness holds end-to-end) but NOT wire-compatible with dalek,
//! libsecp256k1-zkp, or any other implementation. See `transcript.zig`'s
//! module doc comment and `SPEC.md` for the full rationale — this also
//! means the KAT harness below is PROPERTY-and-SOUNDNESS based, never a
//! byte-exact third-party vector.
//!
//! ## Caveats
//!
//! - **Proving is Linux-only.** `rangeproof.prove` draws its secret
//!   blinding material (`alpha`/`rho`/`s_L`/`s_R`/`tau1`/`tau2`) from the
//!   OS via `getrandom(2)` directly (`rangeproof.zig`'s `fillRandom`,
//!   `@compileError` on any non-Linux target — a predictable-blinding
//!   range proof leaks the witness, so this never silently degrades to a
//!   weaker source). `verify`/`verifyIpa`/`commit`/`deltaYZ`/`proveIpa`
//!   (which takes its witness as parameters) and both byte codecs are
//!   platform-independent; only the internal-entropy `prove` path is
//!   gated. `meta.platform` is `.linux` to reflect the most-restrictive
//!   reachable path honestly (porting `fillRandom` to a POSIX/Windows
//!   entropy call would lift this).
//! - **Not constant-time.** `scalarvec.multiScalarMul` skips zero scalars
//!   (a `catch continue` on std's "result is the identity element" error),
//!   so the time to form commitment `A` (built over the secret bit-vector
//!   `a_L`/`a_R`) depends on the committed value's bit pattern — a mild
//!   timing side-channel. A range proof's PRIVACY rests on the proof's
//!   zero-knowledge property (the proof reveals nothing about `v`), not on
//!   constant-time proving, so this does not break the ZK guarantee; it is
//!   documented here for honest threat-modelling of the prover host.
//!
//! ## Layout
//!
//! - `generators.zig` — REAL. Deterministic NUMS generator derivation.
//! - `transcript.zig` — REAL. Self-contained SHA-512 Fiat-Shamir
//!   transcript.
//! - `scalarvec.zig` — REAL. Scalar/vector arithmetic + multi-scalar-mult.
//! - `ipa.zig` — **FABLE CORE (implemented)**: `proveIpa`/`verifyIpa`.
//!   `InnerProductProof`'s struct + codec are REAL.
//! - `rangeproof.zig` — **FABLE CORE (implemented)**: `prove`/`verify`. `commit`,
//!   `deltaYZ`, and `RangeProof`'s struct + codec are REAL.
//! - `gate.zig` — the single switch gating core-dependent tests.
//! - `kat_test.zig` — the property/soundness KAT harness.
//!
//! Provenance: see `NOTICE`.

const std = @import("std");

pub const meta = .{
    .platform = .linux, // prove()'s internal getrandom(2) blinding is Linux-only (see Caveats); verify/codec paths are portable
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "Bünz/Bootle/Boneh/Poelstra/Wuille/Maxwell, \"Bulletproofs: Short Proofs for Confidential Transactions and More\", IEEE S&P 2018 (eprint 2017/1066), §3 (Inner-Product Argument) + §4.1/§4.2 (range proof); dalek-cryptography/bulletproofs (Rust) consulted for construction SHAPE only, no source ported (this module's Fiat-Shamir transcript is its own SHA-512 chain, not Merlin — see transcript.zig); std.crypto.ecc.Ristretto255 supplies the group",
    .deps = .{},
};

pub const gate = @import("gate.zig");

const generators_mod = @import("generators.zig");
pub const Generators = generators_mod.Generators;

const transcript_mod = @import("transcript.zig");
pub const Transcript = transcript_mod.Transcript;

pub const scalarvec = @import("scalarvec.zig");

const ipa_mod = @import("ipa.zig");
pub const InnerProductProof = ipa_mod.InnerProductProof;
pub const IpaError = ipa_mod.IpaError;
/// FABLE CORE (implemented) — see `ipa.zig`.
pub const proveIpa = ipa_mod.proveIpa;
/// FABLE CORE (implemented) — see `ipa.zig`.
pub const verifyIpa = ipa_mod.verifyIpa;
/// The label to start a fresh `Transcript` with for a standalone IPA
/// (`ipa.zig`'s `transcript_domain`).
pub const ipa_domain = ipa_mod.transcript_domain;

const rangeproof_mod = @import("rangeproof.zig");
pub const RangeProof = rangeproof_mod.RangeProof;
pub const ProveError = rangeproof_mod.ProveError;
/// REAL — Pedersen value commitment.
pub const commit = rangeproof_mod.commit;
/// REAL — the verifier's `delta(y,z)` scalar term.
pub const deltaYZ = rangeproof_mod.deltaYZ;
/// FABLE CORE (implemented) — see `rangeproof.zig`.
pub const prove = rangeproof_mod.prove;
/// FABLE CORE (implemented) — see `rangeproof.zig`.
pub const verify = rangeproof_mod.verify;
/// The label to start a fresh `Transcript` with for `prove`/`verify`
/// (`rangeproof.zig`'s `transcript_domain`).
pub const rangeproof_domain = rangeproof_mod.transcript_domain;

/// Re-exported: the std group this module builds on.
pub const Ristretto255 = std.crypto.ecc.Ristretto255;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// refAllDecls walks every pub declaration reachable from this file
// (including the sub-module re-exports above), which is what pulls
// generators.zig/transcript.zig/scalarvec.zig/ipa.zig/rangeproof.zig/
// gate.zig's own `test` blocks into `zig build test-bulletproofs` — a bare
// `pub const x = @import("x.zig")` alone does NOT do this. `kat_test.zig`
// is imported explicitly below since nothing else references it.

const kat_test = @import("kat_test.zig");

test {
    std.testing.refAllDecls(@This());
    _ = kat_test;
}

test "meta.model_after names Bulletproofs + Ristretto255" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Bulletproofs") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Ristretto255") != null);
}

test "meta.deps is empty (std-only)" {
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
}

test "gate is flipped: both ZK cores are implemented" {
    try std.testing.expect(gate.core_implemented);
}
