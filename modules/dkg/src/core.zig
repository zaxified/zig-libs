// SPDX-License-Identifier: MIT

//! core — the five Fable-irreducible GJKR protocol-soundness functions,
//! now IMPLEMENTED (`gate.fable_core_implemented == true`).
//! These are the part where a rushing / Byzantine adversary must be unable
//! to bias the group public key `Q` or learn an honest party's share — the
//! distributed-protocol correctness the module exists to establish. They
//! have NO external byte-exact KAT (GJKR is a randomized interactive
//! protocol; there is no published answer vector), so their soundness is
//! carried by the adversarial round-driver harness (`protocol.zig` +
//! `checks.zig`), not by a golden test — squarely the "no external anchor +
//! nontrivial protocol design space" side of the Fable-tier heuristic.
//!
//! **The bias-prevention ordering, stated once.** `Q = g^{Σ_{i∈QUAL} a_i0}`;
//! an adversary biases `Q` only by choosing whether its contribution is
//! *included* as a function of the honest contributions. Round-1 Pedersen
//! commitments `C_ik = g^{a_ik} h^{b_ik}` are perfectly HIDING, so at the
//! moment `computeQual` freezes membership — from Round-2 complaints and
//! defenses ONLY — the adversary knows nothing about the eventual `Q`.
//! Only after that freeze are the Feldman `A_ik = g^{a_ik}` revealed, and
//! Pedersen's BINDING property forces every QUAL dealer's `A_i0` to open
//! the exact `a_i0` it already committed. Hence `computeQual` takes no
//! Feldman input, and `deriveGroupPublicKey` sums over exactly the frozen
//! set. Feeding any extraction-phase data into the QUAL decision would
//! re-open the rushing-adversary bias even with every equation verifying.
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
    // Reject-don't-panic on adversarial shapes: an empty commitment vector
    // would trip evalCommitmentAt's precondition assert.
    if (commitments.len == 0) return false;
    const lhs = commit.pedersenEvalShare(s, s_prime, h) catch return false;
    const rhs = commit.evalCommitmentAt(commitments, receiver) catch return false;
    return std.crypto.timing_safe.eql([types.Ne]u8, lhs.toBytes(), rhs.toBytes());
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
    if (commitments.len == 0) return false;
    const lhs = commit.feldmanEvalShare(s) catch return false;
    const rhs = commit.evalCommitmentAt(commitments, receiver) catch return false;
    return std.crypto.timing_safe.eql([types.Ne]u8, lhs.toBytes(), rhs.toBytes());
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
    // NOTE deliberately absent from this signature/body: ANY extraction-phase
    // (Feldman) input. QUAL is a pure function of Round-2 Pedersen-phase data
    // — that is the bias-prevention ordering (see the module doc comment).
    if (complaints.len != defense_valid.len) return error.LengthMismatch;
    if (qualified.len != cfg.n) return error.LengthMismatch;

    for (qualified) |*q| q.* = true;

    // Rule (a): an undefended valid complaint disqualifies the accused —
    // the dealer could not broadcast an opening matching its own C_i.
    for (complaints, defense_valid) |c, defended| {
        if (c.accused < 1 or c.accused > cfg.n) continue; // no such dealer to disqualify
        if (!defended) qualified[c.accused - 1] = false;
    }

    // Rule (b): more than `t` DISTINCT complainants disqualify the accused
    // even if each individual complaint was answered. Duplicate complaints
    // from the same complainant count once (else t forged re-sends by one
    // Byzantine party could evict an honest dealer).
    for (qualified, 0..) |*q, d| {
        const did: u32 = @intCast(d + 1);
        var complainers: u32 = 0;
        for (complaints, 0..) |c, k| {
            if (c.accused != did) continue;
            var seen = false;
            for (complaints[0..k]) |prev| {
                if (prev.accused == did and prev.complainant == c.complainant) {
                    seen = true;
                    break;
                }
            }
            if (!seen) complainers += 1;
        }
        if (complainers > cfg.t) q.* = false;
    }

    for (qualified) |q| {
        if (q) return; // at least one dealer survives
    }
    return error.EmptyQual;
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
    if (qualified.len != feldman_a0.len) return error.LengthMismatch;
    var acc: ?commit.Secp256k1 = null;
    for (qualified, feldman_a0) |q, a0| {
        if (!q) continue; // sum over the FIXED QUAL set only — never all dealers
        const p = try a0.point();
        acc = if (acc) |cur| cur.add(p) else p;
    }
    const sum = acc orelse return error.EmptyQual;
    return Element.fromPoint(sum);
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
    if (qualified.len != received.len) return error.LengthMismatch;
    var acc = Scalar.zero;
    var any = false;
    for (qualified, received) |q, r| {
        if (!q) continue; // a non-QUAL dealer's share NEVER enters x_j
        const s = r orelse return error.LengthMismatch;
        acc = acc.add(s);
        any = true;
    }
    if (!any) return error.EmptyQual;
    return acc;
}

// The protocol-level tests that drive these five live in `protocol.zig`/
// `root.zig` (formerly gated; live now that the core is implemented). A
// reference to `gate` keeps its meaning tied to this file.
comptime {
    std.debug.assert(!@import("gate.zig").fable_core_implemented or true);
}

// One direct unit test on the QUAL rules themselves: the round-driver
// harness only ever produces a single complaint, so rule (b) (>t distinct
// complainants) and duplicate-complaint dedup would otherwise be untested.
test "computeQual: undefended complaint, >t distinct complainers, dedup, EmptyQual" {
    const testing = std.testing;
    const cfg: Config = .{ .t = 2, .n = 4 };
    var qual: [4]bool = undefined;

    // No complaints: everyone qualifies.
    try computeQual(&qual, cfg, &.{}, &.{});
    for (qual) |q| try testing.expect(q);

    // A defended complaint keeps the dealer in QUAL (rule a not triggered).
    try computeQual(&qual, cfg, &.{.{ .complainant = 2, .accused = 1 }}, &.{true});
    try testing.expect(qual[0]);

    // An undefended complaint disqualifies (rule a).
    try computeQual(&qual, cfg, &.{.{ .complainant = 2, .accused = 1 }}, &.{false});
    try testing.expect(!qual[0]);
    try testing.expect(qual[1] and qual[2] and qual[3]);

    // Rule (b) EXACT BOUNDARY: the GJKR rule is "MORE THAN t" — exactly
    // t=2 distinct (defended) complainants must NOT evict the dealer. The
    // 3-complainant case below is comfortably over the threshold and would
    // not, by itself, distinguish this ">" from a subtly-wrong ">=".
    try computeQual(&qual, cfg, &.{
        .{ .complainant = 1, .accused = 4 },
        .{ .complainant = 2, .accused = 4 },
    }, &.{ true, true });
    try testing.expect(qual[3]); // exactly t=2: still qualified

    // Rule (b): 3 > t=2 DISTINCT complainants evict dealer 4 even though
    // every single complaint was defended.
    try computeQual(&qual, cfg, &.{
        .{ .complainant = 1, .accused = 4 },
        .{ .complainant = 2, .accused = 4 },
        .{ .complainant = 3, .accused = 4 },
    }, &.{ true, true, true });
    try testing.expect(!qual[3]);
    try testing.expect(qual[0] and qual[1] and qual[2]);

    // Dedup: the SAME complainant re-sending 3 defended complaints must
    // count once — dealer 4 stays qualified.
    try computeQual(&qual, cfg, &.{
        .{ .complainant = 1, .accused = 4 },
        .{ .complainant = 1, .accused = 4 },
        .{ .complainant = 1, .accused = 4 },
    }, &.{ true, true, true });
    try testing.expect(qual[3]);

    // Mismatched parallel arrays / wrong qualified length are rejected.
    try testing.expectError(error.LengthMismatch, computeQual(&qual, cfg, &.{.{ .complainant = 1, .accused = 2 }}, &.{}));
    var short: [3]bool = undefined;
    try testing.expectError(error.LengthMismatch, computeQual(&short, cfg, &.{}, &.{}));

    // Everyone undefended-complained-about: EmptyQual, never a zero key.
    try testing.expectError(error.EmptyQual, computeQual(&qual, cfg, &.{
        .{ .complainant = 2, .accused = 1 },
        .{ .complainant = 1, .accused = 2 },
        .{ .complainant = 1, .accused = 3 },
        .{ .complainant = 1, .accused = 4 },
    }, &.{ false, false, false, false }));
}
