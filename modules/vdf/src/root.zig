// SPDX-License-Identifier: MIT

//! vdf — a pure-Zig **Verifiable Delay Function** (Wesolowski's RSA-group
//! construction: Wesolowski, "Efficient Verifiable Delay Functions", IACR
//! ePrint 2018/623). A VDF computes `y = x^(2^T) mod N` — requiring `T`
//! SEQUENTIAL modular squarings, with no shortcut even given unbounded
//! parallel hardware — plus a succinct proof `π` that lets anyone else
//! check `y` is correct in time independent of `T`. This is the
//! "proof-of-elapsed-time" primitive behind randomness beacons and
//! delay-based leader election (Chia, Ethereum's early VDF research
//! track, Filecoin's discussions of the same); this module implements the
//! RSA hidden-order-group variant, not the class-group variant those
//! systems mostly shipped (see "Trusted-setup caveat" below for why that
//! distinction matters).
//!
//! **Status: COMPLETE.** `group.zig`'s Z_N* wrapper (incl. the RSA-2048
//! Factoring Challenge modulus), `vdf.zig`'s `eval` (the sequential delay
//! itself), `hashToPrime` (the Fiat-Shamir challenge-prime derivation,
//! including its own Miller-Rabin primality test), `pow2Mod` (the
//! mechanical half of `verify`'s check), and `Proof`'s byte codec are all
//! REAL and tested below — as are the two irreducible cores, `prove` (the
//! efficient/streaming Wesolowski prover) and `verify` (the soundness
//! check), implemented in `vdf.zig` per their doc-comment contracts. See
//! `gate.zig` and `SPEC.md`.
//!
//! ## How the pieces fit together
//!
//! ```text
//! eval(N, x, T)              -> y                       (REAL)
//! hashToPrime(N, x, y, T)    -> l  (a challenge prime)   (REAL)
//! prove(N, x, y, T)          -> pi = x^floor(2^T / l)    (REAL, Fable core)
//! verify(N, x, y, pi, T)     -> pi^l * x^r == y, r=2^T mod l  (REAL, Fable core)
//! ```
//!
//! `hashToPrime` is shared, unmodified, by both `prove` and `verify` — it
//! is what makes this a NON-INTERACTIVE proof (Fiat-Shamir: the "random"
//! challenge prime `l` is deterministically derived from the public
//! transcript `(N, x, y, T)` instead of sent by a verifier), and it is
//! also why the exact byte ENCODING of `N`/`x`/`y` fed into it matters:
//! `prove` and `verify` must serialize identically (this module always
//! uses `group.toBytes`'s fixed-width canonical big-endian encoding) or
//! they derive different `l` values and an honest proof fails to verify.
//!
//! ## Trusted-setup caveat — read this before choosing an `N`
//!
//! The VDF's entire security rests on `N`'s factorization being unknown to
//! everyone. Whoever DOES know `N = p*q` can compute `λ(N) = lcm(p-1,
//! q-1)` and then `2^T mod λ(N)` — a CHEAP computation, `O(log T)` modular
//! operations instead of `T` sequential ones — collapsing the entire delay
//! to `y = x^(2^T mod λ(N)) mod N`. This is not a bug in this module; it
//! is the reason the RSA-2048 Factoring Challenge modulus
//! (`group.rsa2048ChallengeModulus`) is the group this module ships as its
//! KAT reference: the challenge was run publicly from 1991 to 2007, RSA-
//! 2048 was never factored or claimed, and — with the factoring challenge
//! long discontinued and no incentive to hide a break — no one is known to
//! hold its factorization. A CALLER-SUPPLIED `N` gets none of that
//! assurance for free: either the caller trusts whoever generated it, or
//! `N` needs its own trusted-setup ceremony (multi-party computation that
//! never reconstructs `p, q` in one place — see the literature on
//! "RSA-UFO"/multi-party RSA modulus generation) before it is safe to use.
//! A CLASS GROUP (the construction Chia/most production VDFs actually
//! ship) sidesteps this entirely — a class group of a negative
//! fundamental discriminant has provably unknown order with NO trusted
//! setup at all, at the cost of a materially more complex group
//! implementation (ideal-class arithmetic, not modular arithmetic). That
//! is a real, useful follow-up (`SPEC.md`'s "Non-goals / follow-ups"), out
//! of scope for this module: this module takes `N` as a parameter and
//! documents the caveat rather than picking a group family that hides it.
//!
//! ## Caveats
//!
//! - **Not constant-time.** `eval`'s sequential-squaring loop and
//!   `hashToPrime`'s search both have data-dependent control flow
//!   (`hashToPrime`'s search LENGTH depends on the binding, and its
//!   internal Miller-Rabin has the same non-constant-time shape
//!   `rsa`/`paillier`/`threshold_ecdsa`'s own primality tests do). None of
//!   `N`, `x`, `y`, `T` are secrets in this construction — a VDF's value
//!   comes from FORCING sequential work on public inputs, not from hiding
//!   anything — so this is not a side-channel concern the way it would be
//!   for, say, RSA key generation.
//! - **`isProbablePrime` is per-module, like three siblings' own copies.**
//!   `rsa`, `paillier`, and `threshold_ecdsa` each already carry a
//!   PRIVATE (non-exported) Miller-Rabin helper of their own; none of the
//!   three is a `pub` export this module could import, so `vdf.zig` has
//!   its OWN — see `meta.deps` below for why that keeps `deps = .{}`
//!   rather than `.{"rsa"}`, and `vdf.zig`'s `isProbablePrime` doc comment
//!   for the one respect in which this copy is NOT a straight port: its
//!   Miller-Rabin witnesses are drawn DETERMINISTICALLY from the candidate
//!   (never `std.crypto.random`), because `hashToPrime` must be a pure
//!   function of its binding — see that file's `deterministicWitnessRandom`
//!   doc comment for why using OS entropy here (as the three siblings
//!   correctly do for KEY GENERATION) would be a liveness bug in a VDF.
//!
//! ## Honest tier note
//!
//! `eval` and `hashToPrime` (including the determinism subtlety above) are
//! MECHANICAL — recipe, not research; get the loop and the domain
//! separation right and they are done. `prove`/`verify` are genuinely
//! Fable-hard, but narrowly so: the "irreducible" part is not the
//! arithmetic (every operation involved is a modular squaring/
//! multiplication this module already has) but two specific judgment
//! calls that are easy to get subtly wrong — (1) the streaming-quotient
//! trick in `prove` (materializing `q = floor(2^T/l)` naively works but
//! defeats the module's own no-big-int design goal; the streaming version
//! requires tracking the long-division remainder correctly in lock-step
//! with `eval`'s squaring loop) and (2) `verify`'s exact relation,
//! specifically that `hashToPrime`'s binding MUST include `y` (the
//! prover's claim), not just `(N, x, T)` — binding only the latter would
//! let a cheating prover pick `l` in advance and forge a proof for a wrong
//! `y`. Neither is large in code volume (`prove`/`verify` are well under
//! 100 lines combined); both are exactly the kind of
//! few-lines-but-wrong-and-everything-breaks logic this repo reserved for
//! a dedicated Fable pass rather than folding into the scaffold — and both
//! are now implemented and verified (completeness/soundness KATs + a
//! naive-vs-streaming quotient cross-check). See `SPEC.md` for the full
//! writeup.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation (no I/O, no wire framing) -> util
    .concurrency = .reentrant, // no shared/global state; Modulus/Fe/Proof are plain value types
    .model_after = "Wesolowski, \"Efficient Verifiable Delay Functions\" (IACR ePrint 2018/623)",
    // NOT `.{"rsa"}`: this module builds its own `std.crypto.ff.Modulus`
    // alias (sized 2048 bits, vs rsa's 4096-bit ceiling) and its own
    // private Miller-Rabin helper (with deterministic, not OS-random,
    // witnesses — see `root.zig`'s "Caveats" section for why that is a
    // correctness requirement here, not a style choice) rather than
    // literally `@import`ing `rsa` — none of `rsa`/`paillier`/
    // `threshold_ecdsa`'s own per-module Miller-Rabin helpers are `pub`
    // anyway, so there is nothing to import even for the parts that ARE
    // conceptually identical.
    .deps = .{},
};

pub const group = @import("group.zig");

const vdf_mod = @import("vdf.zig");

pub const prime_bits = vdf_mod.prime_bits;
pub const prime_bytes = vdf_mod.prime_bytes;
pub const PrimeUint = vdf_mod.PrimeUint;
pub const PrimeModulus = vdf_mod.PrimeModulus;
pub const PrimeFe = vdf_mod.PrimeFe;

/// REAL — the sequential delay itself.
pub const eval = vdf_mod.eval;
/// REAL — the Fiat-Shamir challenge-prime derivation.
pub const hashToPrime = vdf_mod.hashToPrime;
/// REAL — the mechanical half of `verify`'s soundness check.
pub const pow2Mod = vdf_mod.pow2Mod;
/// REAL — the proof struct + its byte codec.
pub const Proof = vdf_mod.Proof;

/// FABLE CORE — the streaming-quotient Wesolowski prover; see `vdf.zig`.
pub const prove = vdf_mod.prove;
pub const ProveError = vdf_mod.ProveError;
/// FABLE CORE — the `π^l * x^r == y` soundness check; see `vdf.zig`.
pub const verify = vdf_mod.verify;
pub const VerifyError = vdf_mod.VerifyError;

pub const gate = @import("gate.zig");

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// refAllDecls walks every pub declaration reachable from this file
// (including the `group`/`vdf_mod`/`gate` re-exports above), which is what
// pulls group.zig's/vdf.zig's/gate.zig's own `test` blocks into
// `zig build test-vdf` — a bare `pub const x = @import("x.zig")` re-export
// alone does NOT do this (see CONVENTIONS.md's "dark-tests rule").
// `kat_test.zig` is imported explicitly below since nothing else
// references it.

const kat_test = @import("kat_test.zig");

test {
    std.testing.refAllDecls(@This());
    _ = kat_test;
}

test "meta.model_after names Wesolowski" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Wesolowski") != null);
}

test "meta.deps is empty (std-only; see root.zig's meta.deps note)" {
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
}

test "gate is flipped: prove/verify cores are implemented" {
    try std.testing.expect(gate.core_implemented);
}
