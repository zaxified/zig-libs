// SPDX-License-Identifier: MIT

//! core — the five Fable-irreducible GJKR protocol-soundness functions,
//! left as `@panic("TODO(fable/core): …")` stubs in this scaffolding pass.
//! These are the part where a rushing / Byzantine adversary must be unable
//! to bias the group public key `Q` or learn an honest party's share — the
//! distributed-protocol correctness the module exists to establish. They
//! have NO external byte-exact KAT (GJKR is a randomized interactive
//! protocol; there is no published answer vector), so their soundness is
//! carried by the adversarial round-driver harness (`protocol.zig` +
//! `checks.zig`), not by a golden test — squarely the "no external anchor +
//! nontrivial protocol design space" side of the Fable-tier heuristic.
//!
//! The signatures below are FINAL: the honest `Dkg` driver already calls
//! them, so the type checker exercises them today even while the bodies
//! panic. A follow-up crypto pass fills the five bodies and flips
//! `gate.fable_core_implemented` to `true`.
//!
//! Reference: R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin, "Secure
//! Distributed Key Generation for Discrete-Log Based Cryptosystems"
//! (J. Cryptology 2007 / EUROCRYPT '99).

const std = @import("std");
const commit = @import("commit.zig");
const types = @import("types.zig");

pub const Scalar = types.Scalar;
pub const Element = types.Element;
pub const Config = types.Config;
pub const Complaint = types.Complaint;

pub const Error = commit.CommitError || error{ EmptyQual, LengthMismatch };

// ── the Fable-irreducible five ───────────────────────────────────────────

/// **CORE 1 — the Round-2 Pedersen share-verification equation.** Returns
/// `true` iff dealer's point-to-point share `(s, s')` for `receiver = j`
/// is consistent with its broadcast Pedersen commitment vector `C`:
///
/// ```text
/// g^s · h^{s'}  ==  Π_k  C_k ^ (j^k)      // = commit.evalCommitmentAt(C, j)
/// ```
///
/// (`commit.pedersenEvalShare(s, s', h)` computes the LHS;
/// `commit.evalCommitmentAt(C, j)` the RHS.) A `false` result is what a
/// receiver turns into a `Complaint` in Round 2. The subtlety this
/// function anchors is soundness: a dealer that broadcast a valid `C` but
/// sent an inconsistent `(s, s')` MUST be caught here (probability 1, not
/// negligible) — this is the binding property that makes the whole
/// bias-prevention argument go through. Must never `@panic` on adversarial
/// input; a malformed point/scalar is a `false` (reject), not an error.
pub fn verifyPedersenShare(
    commitments: []const Element,
    receiver: u32,
    s: Scalar,
    s_prime: Scalar,
    h: Element,
) bool {
    _ = commitments;
    _ = receiver;
    _ = s;
    _ = s_prime;
    _ = h;
    @panic("TODO(fable/core): GJKR Round-2 Pedersen share verification " ++
        "(GJKR §2 Fig.2, step 2): return g^s·h^{s'} == Π_k C_k^{j^k} " ++
        "(commit.pedersenEvalShare vs commit.evalCommitmentAt), constant-time " ++
        "point-equality, false on any decode failure — never panic on bad input.");
}

/// **CORE 2 — the extraction-phase Feldman share-verification equation.**
/// Returns `true` iff QUAL dealer's share `s` for `receiver = j` is
/// consistent with its broadcast Feldman commitment vector `A`:
///
/// ```text
/// g^s  ==  Π_k  A_k ^ (j^k)               // = commit.evalCommitmentAt(A, j)
/// ```
///
/// Run ONLY for dealers already in QUAL, and ONLY after QUAL is fixed. A
/// `false` here (for a dealer whose Pedersen check passed in Round 2) is
/// the trigger for GJKR's public reconstruction of that dealer's `a_i0`
/// (scoped OUT of Phase 1 — see SPEC "Out of scope"); Phase 1 treats a
/// QUAL dealer failing the Feldman check as a hard protocol error. Must
/// never `@panic` on adversarial input.
pub fn verifyFeldmanShare(
    commitments: []const Element,
    receiver: u32,
    s: Scalar,
) bool {
    _ = commitments;
    _ = receiver;
    _ = s;
    @panic("TODO(fable/core): GJKR extraction Feldman share verification " ++
        "(GJKR §2 Fig.2, step 4): return g^s == Π_k A_k^{j^k} " ++
        "(commit.feldmanEvalShare vs commit.evalCommitmentAt); false on decode failure.");
}

/// **CORE 3 — the complaint / disqualification / QUAL logic.** Writes into
/// `qualified` (length `n`, indexed by `dealer - 1`) which dealers survive
/// Round 2. This is the bias-prevention pivot: QUAL is decided PURELY from
/// Round-2 information (Pedersen commitments + complaints + the accused
/// dealers' Round-2 defenses), BEFORE any Feldman commitment is revealed —
/// so a rushing adversary who waits to see others' contributions cannot
/// retroactively drop honest parties to shift `Q`.
///
/// GJKR rule (Fig.2, step 3): a dealer `i` is **disqualified** iff either
///   (a) it fails to broadcast a valid defense `(s_ij, s'_ij)` matching
///       `C_i` for some complainer `j` (`defense_valid[k] == false` for a
///       complaint `k` against `i`), **or**
///   (b) more than `t` parties complained against it.
/// Otherwise it is qualified. `complaints` and `defense_valid` are
/// parallel arrays (`defense_valid[k]` = did dealer `complaints[k].accused`
/// successfully answer `complaints[k].complainant`). Returns
/// `error.LengthMismatch` if the array lengths are inconsistent, or
/// `error.EmptyQual` if no dealer qualifies.
pub fn computeQual(
    qualified: []bool,
    cfg: Config,
    complaints: []const Complaint,
    defense_valid: []const bool,
) Error!void {
    _ = qualified;
    _ = cfg;
    _ = complaints;
    _ = defense_valid;
    @panic("TODO(fable/core): GJKR QUAL determination (GJKR §2 Fig.2, step 3): " ++
        "start all-qualified; disqualify dealer i if it has an undefended " ++
        "complaint (defense_valid==false) OR >t complainers; error.EmptyQual if " ++
        "none survive. THIS decision must depend ONLY on Round-2 data (never on " ++
        "Feldman/extraction data) — that ordering is the bias-prevention crux.");
}

/// **CORE 4 — the bias-prevented group public key.** `Q = Σ_{i∈QUAL} A_i0`
/// where `A_i0 = feldman_a0[i]` is dealer `i+1`'s constant-term Feldman
/// commitment (`= g^{a_i0}`), summed over EXACTLY the qualified dealers.
/// `qualified` and `feldman_a0` are length `n`, index-aligned. The
/// security-critical invariant this function embodies: the sum ranges over
/// the QUAL set fixed in Round 2 (Core 3), never over a set an adversary
/// could still influence — this is *the* reason GJKR is unbiased where
/// naive Pedersen-DKG is not. Returns `error.EmptyQual` if QUAL is empty.
pub fn deriveGroupPublicKey(
    qualified: []const bool,
    feldman_a0: []const Element,
) Error!Element {
    _ = qualified;
    _ = feldman_a0;
    @panic("TODO(fable/core): GJKR public-key extraction (GJKR §2 Fig.2, step 4): " ++
        "Q = Σ_{i: qualified[i]} feldman_a0[i] (elliptic-curve point sum over " ++
        "QUAL ONLY); error.EmptyQual if no dealer qualifies.");
}

/// **CORE 5 — this party's final secret share.** `x_j = Σ_{i∈QUAL} s_ij`,
/// where `received[i]` = dealer `i+1`'s point-to-point share to this party
/// `j` (`null` if none was accepted from that dealer). `qualified` and
/// `received` are length `n`, index-aligned; a `qualified[i] == true` with
/// `received[i] == null` is a protocol inconsistency (`error.LengthMismatch`).
/// The resulting `x_j` is this party's share of the group secret
/// `x = Σ_{i∈QUAL} a_i0`, with `x·G == Q` and any `t` such shares Lagrange-
/// reconstructing `x`.
pub fn combineKeyShare(
    qualified: []const bool,
    received: []const ?Scalar,
) Error!Scalar {
    _ = qualified;
    _ = received;
    @panic("TODO(fable/core): GJKR share combination (GJKR §2 Fig.2, step 4): " ++
        "x_j = Σ_{i: qualified[i]} received[i].? (scalar sum mod q over QUAL); " ++
        "error.LengthMismatch if a qualified dealer has no accepted share.");
}

// The stubs above intentionally have no runnable test here; the gated
// tests that drive them live in `protocol.zig`/`root.zig` and SKIP while
// `gate.fable_core_implemented == false`. A reference to `gate` keeps its
// meaning tied to this file.
comptime {
    std.debug.assert(!@import("gate.zig").fable_core_implemented or true);
}
