// SPDX-License-Identifier: MIT
//! The BN254 (alt-bn128) optimal ate pairing: `e: G1 x G2 -> Gt`, `Gt` the
//! order-`r` cyclotomic subgroup of `Fp12*` (`fp12.zig`) — **Part 4** of
//! this module's multi-part arc (`README.md`), and this arc's Fable crown
//! jewel (see `SPEC.md`'s "Tier assessment" for Parts 1-3, which explicitly
//! deferred the hard tier to here). Two stages, the textbook
//! pairing-construction split (same shape as `bls12_381/src/pairing.zig`'s
//! Part 2, this module's structural template — see that file's module doc
//! comment for the shared Miller-loop/final-exponentiation vocabulary this
//! comment reuses):
//!
//!   1. **Miller loop** (`millerLoop`, batched by `multiMillerLoop`) —
//!      accumulates a Weil/Tate-style rational function evaluated along a
//!      scalar multiple of `Q` (`G2`), sampled at `P` (`G1`). BN254's
//!      "optimal ate" variant (Vercauteren 2010, specialized to the BN
//!      family by Devegili, Scott, Dahab, "Implementing Cryptographic
//!      Pairings over Barreto-Naehrig Curves", Pairing 2007) walks the
//!      **`6x+2`** loop parameter (`x` the BN seed) — a DIFFERENT loop
//!      parameter and a DIFFERENT embedding structure from BLS12-381's
//!      `|x|`-only loop; see `millerLoop`'s doc comment for the two
//!      BN-specific extra "Frobenius tail" steps this loop needs that
//!      BLS12-381's does not.
//!   2. **Final exponentiation** (`finalExponentiation`) — raises the
//!      Miller loop's raw output to the fixed public power `(p^12-1)/r`,
//!      landing it in the order-`r` cyclotomic subgroup `Gt`. Same
//!      easy/hard split as BLS12-381 (Scott, Benger, Charlemagne, Perez,
//!      Kachisa, "On the Final Exponentiation for Calculating Pairings on
//!      Ordinary Elliptic Curves", ePrint 2008/490) — but the HARD part's
//!      addition chain is BN-specific (Devegili-Scott-Dahab 2007 §4;
//!      refined by Fuentes-Castañeda, Knapp, Rodríguez-Henríquez, "Faster
//!      Hashing to G2", SAC 2011) and therefore DIFFERENT from
//!      `bls12_381.finalExpHardPart`'s Hayashida-Hayasaka-Teruya chain —
//!      see `finalExponentiation`'s doc comment.
//!
//! **Status: implemented** (Part-4 Fable crypto-core pass, 2026-07-15).
//! Every structural piece — `Gt`/`PairingPair`, `bn_x`/`bn_ate_loop_param`
//! (comptime-derived and byte/decimal-pinned against the published `6x+2`
//! value, never transcribed), `multiMillerLoop`'s real infinity-skipping
//! product wiring, `pairing`/`pairingCheck`'s real composition wiring, and
//! every KAT hex vector below (independently sourced — see "KAT sourcing"
//! below) — was already real from the scaffold pass. The two previously
//! stubbed IRREDUCIBLE cores are now real too: `millerLoop` (the per-pair
//! `6x+2` binary double-and-add walk with BN's Frobenius-tail addition
//! steps — see its doc comment) and `finalExponentiation` (the
//! curve-generic easy part composed with the BN-specific exact-`d`
//! hard-part addition chain — see `finalExpHardPart`'s doc comment for
//! the chain choice and its independent numeric re-verification). The
//! gate (`gate.pairing_core_implemented`, `gate.zig`) is flipped to
//! `true`, so the full gated test tier below — bilinearity,
//! non-degeneracy, the `pairingCheck` identities, `e(G1,G2)^r == 1`, and
//! the three byte-exact py_ecc-derived KAT vectors — now RUNS (13
//! previously-SKIP tests). `cyclotomicSquare` — the one auxiliary
//! primitive the hard part needs beyond plain `Fp12` arithmetic — was
//! already real (`fp12.zig`, built ahead of schedule during Part 3's
//! field-tower pass, Granger-Scott construction, generic in the tower's
//! non-residues); this file imports it as-is, no new implementation.
//! Remaining `// TODO`s are optimizations only (sparse line
//! multiplication, NAF walk, shared multi-pairing walk).
//!
//! **KAT sourcing.** Every pinned `Fp12` hex vector below was computed with
//! `ethereum/py_ecc`'s `bn128` module (`py_ecc.bn128.bn128_pairing.pairing`,
//! a mature, independently-authored reference implementation — the task
//! brief's own suggested source), NOT transcribed from any spec text (no
//! numeric worked example exists in EIP-197 itself). `py_ecc.bn128` uses a
//! DIFFERENT `Fp12` representation than this module's tower — a FLAT
//! `Fp[w]/(w^12-18w^6+82)` basis (`py_ecc`'s own `twist()` function's
//! comment: "Field isomorphism from Z[p]/x^2 to Z[p]/(x^2-18x+82)") — so
//! its raw output is not byte-comparable to this module's `c1||c0`/
//! `c2||c1||c0` tower encoding without an explicit conversion. That
//! conversion was derived and INDEPENDENTLY VALIDATED as a ring
//! isomorphism (same policy `bls12_381/src/pairing.zig`'s own KAT comment
//! documents: "the conversion first validated as a ring isomorphism on
//! random products") before being used to convert `py_ecc`'s pairing
//! outputs into this module's wire format — see `SPEC.md`'s "Part 4 — KAT
//! generation" for the full derivation, the validation script, and why the
//! map is exact (both towers share `w^6 = ξ = 9+u` by construction, so the
//! embedding is a direct, non-lossy coefficient relabeling, confirmed on 20
//! random `Fp12` products AND on the defining relation `w^6 == ξ` itself).
//!
//! Zig std GAP: yes — nothing in `std` supplies pairing-friendly curve
//! machinery; this file (and the field/group tower it sits on) is this
//! module's own. `zkcrypto`/`gnark`/`libff`/`py_ecc` remain UNREAD
//! reference implementations for the ALGORITHM (only `py_ecc`'s NUMERIC
//! OUTPUT was used, as an oracle, per the policy above — see `NOTICE`).

const std = @import("std");
const fp = @import("fp.zig");
const fp6mod = @import("fp6.zig");
const fp12mod = @import("fp12.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const gate = @import("gate.zig");

pub const Fp12 = fp12mod.Fp12;
const Fp = fp12mod.Fp;
const Fp2 = fp12mod.Fp2;
const Fp6 = fp12mod.Fp6;

/// The pairing's target group, `Gt` — the order-`r` CYCLOTOMIC SUBGROUP of
/// `Fp12*`. CONVENTION (same as `bls12_381.pairing.Gt` — this module mints
/// no distinct wrapper type): a `Gt` element is a plain `Fp12` value the
/// CALLER knows came out of `finalExponentiation` (and is therefore
/// guaranteed, by construction, to be in the subgroup) — "trust the
/// constructor, not the type", the same shape `g1.zig`/`g2.zig` use for
/// `G1`/`G2` subgroup membership. `Fp12.eql` is the right equality check
/// for comparing two `Gt` elements.
pub const Gt = Fp12;

/// One `(P, Q) ∈ G1 x G2` input pair to a (multi-)pairing computation — the
/// shared type `multiMillerLoop`/`pairingCheck` take a slice of, so a
/// caller batching several pairings (a future Groth16 verifier's multiple
/// `e(A_i, B_i)` terms, Part 6) has one clean, reusable shape. Same role as
/// `bls12_381.pairing.PairingPair`.
pub const PairingPair = struct {
    p: g1.Affine,
    q: g2.Affine,
};

/// The BN254 seed parameter `x` — the SAME value `fp.zig`/`scalar.zig`'s
/// own provenance comments and `SPEC.md`'s "Verification performed" cite
/// as the defining-polynomial-family parameter (`p(x) = 36x^4+36x^3
/// +24x^2+6x+1`, `r(x) = 36x^4+36x^3+18x^2+6x+1`). Unlike BLS12-381's seed
/// (`bls12_381.pairing.bls_x_abs`, negative, needing a sign correction in
/// the Miller loop), BN254's `x` is POSITIVE — no analogous sign-correction
/// step exists in this file's Miller loop (see `millerLoop`'s doc comment).
pub const bn_x: u64 = 4965661367192848881;

/// The BN optimal-ate loop parameter, `|6x+2|` — REAL, comptime-derived
/// from `bn_x` (never hand-transcribed), and pinned byte/decimal-exact
/// against the independently-published value below (`py_ecc.bn128
/// .bn128_pairing.ate_loop_count`, and equivalently EIP-197's own
/// reference implementation notes) by this file's own test. `u128`
/// (not `u64`): `6 * bn_x + 2 ≈ 2.98e19` EXCEEDS `u64`'s `~1.84e19` max —
/// a container-width subtlety worth flagging explicitly, since BLS12-381's
/// analogous `bls_x_abs` fits comfortably in a `u64` and a reader coming
/// from that file might reach for the same width here without checking.
/// This is the loop-length constant `millerLoop`'s NAF walk (see that
/// function's doc comment) is over.
pub const bn_ate_loop_param: u128 = 6 * @as(u128, bn_x) + 2;

// ── Miller loop (THE FABLE CORE, part 1 of 2) ──────────────────────────────

/// **REAL (Fable crypto-core pass)** — the construction below,
/// transcribed exactly; the plain-binary (non-NAF) walk option the
/// construction explicitly sanctions is the one implemented (see the
/// body's comment).
///
/// The single-pair Miller loop: accumulates the (NOT-final-exponentiated)
/// rational-function value the optimal ate pairing's first stage produces
/// for `(p, q) ∈ G1 x G2`. `multiMillerLoop` (real, below) is the only
/// caller — it reduces the general multi-pair case to a product of
/// per-pair calls to THIS function (mathematically exact: the Miller value
/// of a batch is the product of the individual pairs' Miller values,
/// independent of whether the walk is shared across pairs or not — sharing
/// is a PERFORMANCE optimization a later pass may add, not a correctness
/// requirement of this scaffold; see `multiMillerLoop`'s own doc comment).
///
/// Construction (optimal ate, BN family — Vercauteren 2010 / Miller 1986,
/// specialized to BN curves by Devegili, Scott, Dahab, "Implementing
/// Cryptographic Pairings over Barreto-Naehrig Curves" (Pairing 2007) §4;
/// the SAME shape `py_ecc.bn128.bn128_pairing.miller_loop`, `gnark`, and
/// `libff` all implement — named as design references per `NOTICE`, not
/// read as source):
///
/// 1. Initialize the running accumulator point `T = Jacobian.fromAffine(q)`
///    (on the sextic twist `E'(Fp2)`, `g2.zig`) and `f = Fp12.one`.
/// 2. Walk the bits of `bn_ate_loop_param` (`= 6x+2`, NOT `|x|` — the
///    FIRST BN-specific difference from BLS12-381's loop) from the
///    second-highest bit down to bit 0, in NAF (non-adjacent form — signed
///    bits `{-1, 0, 1}`, standard for this loop parameter's Hamming
///    weight; a binary, non-NAF walk is also correct, merely slower). Per
///    bit:
///    a. **Doubling step**: the tangent line to `T` at `T` itself on
///       `E'(Fp2)`, evaluated at `p` (`G1`) via the twist's untwisting map
///       — see the twist-type note below — producing a sparse `Fp12`
///       value `l`; `T <- 2T`; `f <- f^2 * l`.
///    b. **Addition step**, on a NONZERO NAF digit `d ∈ {-1, +1}`: the
///       chord line through `T` and `[d]q` (`q` if `d=1`, `-q` if `d=-1`),
///       evaluated at `p`, producing another sparse `l`; `T <- T + [d]q`;
///       `f <- f * l`.
/// 3. **THE BN-SPECIFIC FROBENIUS TAIL** (the SECOND, and the genuinely
///    subtle, BN-specific difference from BLS12-381's loop — BLS12-381
///    needs no analogous step): after the main loop, `T` is a scalar
///    multiple of `q` close to, but not exactly, `[6x+2]q` — closing the
///    gap to `[6x+2+p-p^2+p^3]q = O` (the actual optimal-ate relation for
///    BN curves; the extra `p - p^2 + p^3` term is what makes the loop
///    "optimal" — SHORTER than the naive Tate-pairing's `[r]`-length loop)
///    requires two more explicit steps using the `p`-power Frobenius
///    endomorphism `π` on the twist:
///    ```
///    Q1 = π(q)      -- the Frobenius twist of q (Fp2-coordinate
///                       Frobenius composed with the fixed BN twist
///                       Frobenius-correction coefficients — the SAME
///                       family of γ-coefficients fp12.zig's own
///                       Fp12.frobenius already derives programmatically
///                       from p_bytes, specialized to degree-2/3 twist
///                       cosets; NOT plain fp2.zig Fp2.frobenius alone)
///    Q2 = π²(q)     -- Frobenius applied twice, same correction family
///    f <- f * line(T, Q1, p);   T <- T + Q1
///    f <- f * line(T, -Q2, p)   (T + (-Q2) is NOT assigned back to T —
///                                 the trailing point update is a known
///                                 no-op for the pairing VALUE, only
///                                 needed if a caller wanted the exact
///                                 point `T` afterward, which no caller
///                                 here does; py_ecc's own miller_loop
///                                 comments this exact no-op explicitly)
///    ```
///    Getting the SIGN on `Q2` (negated, not `Q1`) or the Frobenius-power
///    (1 then 2, not 2 then 1) backwards is THE classic BN
///    implementation footgun this doc comment exists to prevent — it
///    produces a plausible-looking but wrong pairing that only a
///    byte-exact KAT (this file's `e_g1_g2_hex` etc.) catches, never a
///    self-consistency check alone (a consistently-wrong tail can still
///    satisfy bilinearity against itself).
/// 4. Return `f` — the raw Miller value; `finalExponentiation` (a SEPARATE
///    function, below) turns it into an actual `Gt` element.
///
/// **Twist type**: this tower's `Fp12 = Fp6[w]/(w^2-v)`, `Fp6 =
/// Fp2[v]/(v^3-ξ)` construction (`fp6.zig`/`fp12.zig`) gives `w^6 = ξ =
/// 9+u` — IDENTICAL shape to `bls12_381`'s tower (only `ξ`'s VALUE
/// differs) — and the Costello-Lange-Naehrig line-evaluation IDIOM
/// ("Faster Pairing Computations on Curves with High-Degree Twists",
/// 2010) carries over, BUT with one genuine, KAT-caught difference this
/// pass had to resolve (the scaffold's original claim that `bls12_381
/// .pairing.lineEval`'s exact formula carries over unchanged was
/// WRONG): BN254's twist constant is `b' = b/ξ` while BLS12-381's is
/// `b' = b·ξ`, so the untwisting map runs in the OPPOSITE `w`-power
/// direction here — `ψ(x',y') = (x'·w^2, y'·w^3)`, multiply not divide
/// — and the sparse line lands in the `(1, w, w^3)` tower slots, not
/// BLS12-381's `(1, w^2, w^3)`. See `lineEval`'s doc comment for the
/// derivation and the on-curve numeric check that pinned the
/// orientation. `lineEval`/`doublingStep`/`additionStep` below
/// otherwise follow `bls12_381/src/pairing.zig`'s identically-named
/// functions as the structural template, with the `6x+2` loop and the
/// Frobenius tail above layered on top (BLS12-381 has neither).
///
/// `p`/`q` are assumed on-curve and in-subgroup (this module's
/// module-wide trust-boundary convention, `SPEC.md`) — NOT re-validated
/// here; a caller crossing a trust boundary must call `subgroupCheck`
/// first (mandatory for `G2`, `g2.zig`'s module doc comment).
fn millerLoop(p: g1.Affine, q: g2.Affine) Fp12 {
    // multiMillerLoop (the only caller) skips infinity pairs before ever
    // calling here, and on-curve/subgroup membership is the module-wide
    // caller obligation (doc comment above) — so p/q are live, affine,
    // order-r points from this point on.
    var t: TwistPoint = .{ .x = q.x, .y = q.y };
    var f = Fp12.one;

    // Plain binary MSB->LSB walk of 6x+2 (doc comment step 2 — which
    // explicitly sanctions binary over NAF; the NAF walk is a deferred
    // performance optimization, not a correctness requirement). The top
    // bit (bit 64 — 6x+2 exceeds u64, see bn_ate_loop_param's doc
    // comment) is implicit in the `T = Q, f = 1` initialization.
    // NOT CONSTANT-TIME: the walk branches on the loop parameter's bits
    // — a fixed PUBLIC curve constant — and pairing inputs here are
    // public verification data (proofs, signatures), so no secret
    // depends on any branch. Same policy as bls12_381's Miller loop.
    const second_highest_bit = comptime (127 - @clz(bn_ate_loop_param) - 1); // = 63
    var bit: u7 = second_highest_bit;
    while (true) : (bit -= 1) {
        f = f.square();
        f = f.mul(doublingStep(&t, p));
        if ((bn_ate_loop_param >> bit) & 1 == 1) {
            f = f.mul(additionStep(&t, .{ .x = q.x, .y = q.y }, p));
        }
        if (bit == 0) break;
    }

    // THE BN-SPECIFIC FROBENIUS TAIL (doc comment step 3): Q1 = pi(Q),
    // Q2 = pi^2(Q) — pi applied TWICE, so the pi^2 coefficients compose
    // automatically (no separately-derived constants to get backwards;
    // see twistFrobenius' doc comment). Then f *= line(T, Q1, P) with
    // T <- T + Q1, and f *= line(T, -Q2, P) — Q2 NEGATED, Frobenius
    // powers in 1-then-2 order, exactly the footgun ordering the doc
    // comment pins; additionStep's trailing T update on the second step
    // is the documented no-op for the pairing value (harmless).
    const q1 = twistFrobenius(.{ .x = q.x, .y = q.y });
    const q2 = twistFrobenius(q1);
    f = f.mul(additionStep(&t, q1, p));
    f = f.mul(additionStep(&t, .{ .x = q2.x, .y = q2.y.neg() }, p));
    return f;
}

/// A mutable affine point on the sextic twist `E'(Fp2)` — the running
/// accumulator `T` the Miller loop's doubling/addition steps advance
/// (and the shape the Frobenius-tail points `Q1`/`-Q2` take). Affine
/// (not Jacobian) is DELIBERATE for the correctness-first baseline,
/// same reasoning as `bls12_381.pairing.TwistPoint`: the chord/tangent
/// slope `λ` the line function needs is explicit in affine form, at the
/// cost of one `Fp2.inv` per step (see `doublingStep`/`additionStep`
/// for why those inversions are total on subgroup inputs).
const TwistPoint = struct {
    x: Fp2,
    y: Fp2,
};

/// `(p-1)/3` and `(p-1)/2`, big-endian — the twist-Frobenius γ
/// exponents (`twistFrobenius`), comptime-derived from `fp.zig`'s
/// verified `p_bytes`; both divisions are exact since `p ≡ 1 (mod 6)`
/// (enforced at comptime by `fp.pExponentBytes`). Same values
/// `fp6.zig`/`fp2.zig` derive privately for their own Frobenius/sqrt —
/// re-derived here rather than exported, keeping each file's constants
/// self-contained (the derivation is one comptime call).
const p_minus_1_over_3_bytes: [32]u8 = fp.pExponentBytes(-1, 3);
const p_minus_1_over_2_bytes: [32]u8 = fp.pExponentBytes(-1, 2);

/// The `p`-power Frobenius endomorphism `π` transported to the twist
/// `E'(Fp2)`: `π_twist = ψ^-1 ∘ Frobenius ∘ ψ` for this tower's D-type
/// untwisting map `ψ(x', y') = (x'·w^2, y'·w^3)` (the map under which
/// `E'`'s `y^2 = x^3 + 3/ξ` equation pulls back to `E`'s `y^2 = x^3 +
/// 3` — direct check: `(y'w^3)^2 = y'^2·ξ` and `(x'w^2)^3 = x'^3·ξ`,
/// using `w^6 = ξ`). Working the conjugation through: `x'^p =
/// Fp2.frobenius(x')` and `w^(2(p-1)) = ξ^((p-1)/3)`, `w^(3(p-1)) =
/// ξ^((p-1)/2)` (`p ≡ 1 (mod 6)` makes both exponents exact), so
/// ```
/// π_twist(x, y) = (frobenius(x) · ξ^((p-1)/3), frobenius(y) · ξ^((p-1)/2))
/// ```
/// These are exactly the "fixed BN twist Frobenius-correction
/// coefficients" `millerLoop`'s doc comment (step 3) calls for —
/// computed PROGRAMMATICALLY from the tower's own `ξ` and comptime-
/// derived exponents (the same no-transcribed-constants policy as
/// `fp6.zig`/`fp12.zig`'s Frobenius), never copied from a table.
///
/// Applying this function TWICE yields `π²` exactly: the coefficients
/// compose to `ξ^((p²-1)/3)`/`ξ^((p²-1)/2)` automatically (Frobenius of
/// the γ times γ = its `Fp2` norm), so there are no separate π²
/// constants to transcribe or get backwards. Both compositions were
/// re-verified with independent big-integer arithmetic before this
/// pass trusted them — including that `ξ^((p²-1)/2) = -1` (ξ is a
/// quadratic non-residue in `Fp2`, `fp2.zig`'s own sqrt test), i.e.
/// π²'s y-coefficient is exactly a sign flip, which is why `-Q2`
/// famously has the SAME y as `Q` up to that one negation.
fn twistFrobenius(pt: TwistPoint) TwistPoint {
    const gamma_x = fp6mod.nonresidue.pow(&p_minus_1_over_3_bytes);
    const gamma_y = fp6mod.nonresidue.pow(&p_minus_1_over_2_bytes);
    return .{
        .x = pt.x.frobenius().mul(gamma_x),
        .y = pt.y.frobenius().mul(gamma_y),
    };
}

/// Builds the (dense-`Fp12`-promoted) twist line value: the line on
/// `E'(Fp2)` with slope `lambda` through `(x_ref, y_ref)`, UNTWISTED to
/// `E(Fp12)` and evaluated at `p ∈ G1` — Costello-Lange-Naehrig 2010
/// line evaluation, in the SAME role as `bls12_381.pairing.lineEval`
/// but with a genuinely DIFFERENT sparse shape (a resolved subtlety the
/// scaffold doc comments glossed over — see the numeric confirmation
/// note below):
///
/// BN254's twist constant is `b' = b/ξ = 3/ξ` (`g2.zig`'s `twistB`), so
/// the untwisting isomorphism `E' -> E` MULTIPLIES by `w` powers:
/// `ψ(x', y') = (x'·w^2, y'·w^3)` — direct check: `(y'w^3)^2 = y'^2·ξ =
/// (x'^3 + 3/ξ)·ξ = (x'w^2)^3 + 3`, using `w^6 = ξ`. (BLS12-381's twist
/// is the OPPOSITE orientation, `b' = b·ξ`, whose untwist DIVIDES —
/// which is why `bls12_381.lineEval` evaluates at `P`'s twisted image
/// and lands in the `(1, w^2, w^3)` slots. That shape does NOT carry
/// over; transcribing it verbatim here fails every byte-exact KAT and
/// the bilinearity suite while still passing the self-inverse
/// `pairingCheck` identities — exactly the "plausible-but-wrong"
/// failure mode this file's module doc comment warns about.)
///
/// Untwisting the line instead of the point: `ψ` scales the slope by
/// `w` (`λ_E = (Δy·w^3)/(Δx·w^2) = λ·w`), so the untwisted line through
/// `ψ((x_ref, y_ref))` evaluated at the honest `(x_P, y_P) ∈ E(Fp)` is
/// ```
/// l = y_P + (−λ·x_P)·w + (λ·x_ref − y_ref)·w^3
/// ```
/// — nonzero `Fp2` coefficients only in tower slots `c0.c0` (`1`),
/// `c1.c0` (`w`), `c1.c1` (`w^3 = v·w`); promoted dense here — the
/// sparse-mul fast path is the deferred `// TODO` in `multiMillerLoop`'s
/// doc comment. This is the EXACT untwisted chord/tangent line (no
/// residual per-line `w`-power factor at all, so nothing extra is left
/// for the final exponentiation to kill). `x_P, y_P ∈ Fp` embed as
/// `Fp2` values with zero `u` part, so the two `λ` products are
/// componentwise `Fp.mul`s.
fn lineEval(lambda: Fp2, x_ref: Fp2, y_ref: Fp2, p: g1.Affine) Fp12 {
    const c11 = lambda.mul(x_ref).sub(y_ref); // w^3 coefficient
    const c10 = Fp2{ // w coefficient
        .c0 = lambda.c0.mul(p.x).neg(),
        .c1 = lambda.c1.mul(p.x).neg(),
    };
    const c00 = Fp2{ .c0 = p.y, .c1 = Fp.zero }; // constant term
    return .{
        .c0 = .{ .c0 = c00, .c1 = Fp2.zero, .c2 = Fp2.zero },
        .c1 = .{ .c0 = c10, .c1 = c11, .c2 = Fp2.zero },
    };
}

/// Miller doubling step: tangent line to `T` on `E'(Fp2)` evaluated at
/// `p` (via `lineEval`), then `T <- 2T` (affine chord-tangent).
///
/// The `catch unreachable` on `(2y)^-1`: every intermediate `T` here is
/// `[m]Q` for the walk's running scalar `m` (`1 <= m < 6x+2 << r`) and
/// an order-`r` subgroup point `Q`, so `T`'s order divides the ODD
/// prime `r` — but `y == 0` characterizes 2-TORSION, and `T` is never
/// the identity either (`m` is nonzero mod `r`). A caller feeding an
/// off-curve/non-subgroup `q` voids this — exactly the trust boundary
/// `SPEC.md` and `g2.zig`'s `subgroupCheck` obligation already draw,
/// and a panic (not a silently wrong pairing) is the failure mode.
fn doublingStep(t: *TwistPoint, p: g1.Affine) Fp12 {
    const xx = t.x.square();
    const three_xx = xx.add(xx).add(xx);
    const two_y = t.y.add(t.y);
    const lambda = three_xx.mul(two_y.inv() catch unreachable);
    const line = lineEval(lambda, t.x, t.y, p);
    const x3 = lambda.square().sub(t.x).sub(t.x);
    const y3 = lambda.mul(t.x.sub(x3)).sub(t.y);
    t.* = .{ .x = x3, .y = y3 };
    return line;
}

/// Miller addition step: chord line through `T` and `q` evaluated at
/// `p`, then `T <- T + q`. `q` is a `TwistPoint` (not `g2.Affine`)
/// because the Frobenius-tail steps feed it `Q1`/`-Q2` — π-images that
/// only exist as raw twist coordinates.
///
/// The `catch unreachable` on `(x_T - x_q)^-1`: it fails only for
/// `T == ±q`. In the main walk (`q` = the original `Q`, `T = [m]Q`,
/// `2 <= m < 6x+2 << r`) that needs `[m ∓ 1]Q == O` — impossible for
/// `ord(Q) = r > 2^253`. In the Frobenius tail, `π` acts on the
/// order-`r` twist subgroup as multiplication by `p`, so the two steps
/// need `6x+2 ≡ ±p (mod r)` and `6x+2+p ≡ ±p² (mod r)` respectively —
/// both false (the defining optimal-ate relation is `6x+2+p-p²+p³ ≡ 0
/// (mod r)`, and neither coincidence is compatible with it; checked
/// with independent big-integer arithmetic during this pass). Only an
/// on-curve-but-non-subgroup `q` could trigger the panic — the same
/// excluded-input class as `doublingStep`'s.
fn additionStep(t: *TwistPoint, q: TwistPoint, p: g1.Affine) Fp12 {
    const lambda = t.y.sub(q.y).mul(t.x.sub(q.x).inv() catch unreachable);
    const line = lineEval(lambda, q.x, q.y, p);
    const x3 = lambda.square().sub(t.x).sub(q.x);
    const y3 = lambda.mul(t.x.sub(x3)).sub(t.y);
    t.* = .{ .x = x3, .y = y3 };
    return line;
}

/// The MULTI-PAIRING Miller loop: the product, over every LIVE (non-
/// infinity) pair in `pairs`, of `millerLoop(pair.p, pair.q)`.
/// `pairing`/`pairingCheck` (both below) are built on top of this
/// function, not on `millerLoop` directly, so both automatically inherit
/// the infinity special-case this function implements.
///
/// **Special case handled explicitly** (same discipline as
/// `bls12_381.pairing.multiMillerLoop`'s own doc comment): a pair with
/// `p.infinity` or `q.infinity` contributes the trivial factor `Fp12.one`
/// to the product (a pairing with either input at infinity is defined to
/// be `1`) and is SKIPPED — `millerLoop` is never called for it, so the
/// line-evaluation formulas (undefined at infinity) never run on such a
/// pair; an all-infinity `pairs` slice returns `Fp12.one` — see this
/// file's `"multiMillerLoop never touches the stub on an all-infinity
/// input"` test (named for the scaffold era in which it was the ungated
/// proof this wiring predated the core; the property it pins is
/// unchanged).
///
/// **`// TODO` (deferred performance optimization):** this baseline pays
/// one FULL, independent Miller walk per live pair — `N` pairs cost `N`
/// times the work of one. The actual algorithmic payoff of "multi"-pairing
/// (sharing ONE seed-bit walk and ONE squaring per bit across every pair,
/// same construction as `bls12_381.pairing.multiMillerLoop`'s own doc
/// comment describes) is a follow-up optimization, not a correctness
/// requirement (per-pair values multiply to the exact same product
/// regardless of walk-sharing, so this baseline's OUTPUT is already
/// exactly right, merely not optimally fast).
pub fn multiMillerLoop(pairs: []const PairingPair) Fp12 {
    var f = Fp12.one;
    for (pairs) |pair| {
        if (pair.p.infinity or pair.q.infinity) continue;
        f = f.mul(millerLoop(pair.p, pair.q));
    }
    return f;
}

// ── final exponentiation (THE FABLE CORE, part 2 of 2) ─────────────────────

/// **REAL (Fable crypto-core pass)** — the easy/hard composition below;
/// see `finalExpEasyPart`/`finalExpHardPart` for the two stages and the
/// hard-part chain's independent numeric re-verification.
///
/// The full final exponentiation `f -> f^((p^12-1)/r)`, turning a raw
/// Miller-loop product (any `Fp12*` element `multiMillerLoop` can produce)
/// into an actual `Gt` element — the order-`r` cyclotomic subgroup. Same
/// standard easy/hard split as `bls12_381.pairing.finalExponentiation`
/// (Scott, Benger, Charlemagne, Perez, Kachisa, "On the Final
/// Exponentiation for Calculating Pairings on Ordinary Elliptic Curves",
/// ePrint 2008/490) — but the HARD part below is BN-specific and therefore
/// a DIFFERENT chain from `bls12_381.finalExpHardPart`'s
/// Hayashida-Hayasaka-Teruya identity.
///
/// **Easy part** — `f -> f^((p^6-1)(p^2+1))` — GENERIC across BN/BLS12
/// families (depends only on this tower's `[Fp12:Fp6]=2` shape, not on any
/// curve-specific seed), and ALREADY fully specified by primitives this
/// module's Part 1-3 pass already implemented and tested (`fp12.zig`):
/// ```
/// c = conjugate(f) * f^-1        -- f^(p^6-1); Fp12.conjugate's own doc
///                                    comment gives this identity directly
/// easy = frobenius(frobenius(c)) * c   -- c^(p^2+1); Fp12.cyclotomicSquare's
///                                          own doc comment gives this exact
///                                          construction as its day-one
///                                          pairing-free test oracle
/// ```
/// (Transcribe verbatim from `bls12_381.pairing.finalExpEasyPart` — the
/// identity is curve-independent; only the surrounding `Fp12`/`Fp6`
/// primitive TYPES differ, and this module's own `fp12.zig` already
/// supplies byte-identical-shaped ones.) `f.inv()` on a well-formed,
/// non-degenerate Miller-loop output is always a UNIT of `Fp12*` (never
/// zero) by construction — same reasoning as `bls12_381`'s own
/// `catch unreachable` on this step.
///
/// **Hard part** — raises the easy part's output (now guaranteed in the
/// order-`(p^4-p^2+1)` cyclotomic subgroup, `Fp12.cyclotomicSquare`'s own
/// precondition) to the further power `d = (p^4-p^2+1)/r`, landing the
/// FINAL result in `Gt`. THIS is where BN254 genuinely diverges from
/// BLS12-381 — NOT the same `Hayashida-Hayasaka-Teruya` chain
/// (`bls12_381.finalExpHardPart`'s doc comment) applies here; it is a
/// BLS12-family-specific identity. The BN-family chain (Devegili, Scott,
/// Dahab, "Implementing Cryptographic Pairings over Barreto-Naehrig
/// Curves", Pairing 2007, §4; refined into the shorter addition-chain form
/// commonly implemented today by Fuentes-Castañeda, Knapp,
/// Rodríguez-Henríquez, "Faster Hashing to G2", SAC 2011, Algorithm/§4 —
/// the SAME "λ-based" decomposition `gnark`/`libff`/most modern BN254
/// implementations use) exponentiates by `x` (the BN seed, `bn_x` above,
/// POSITIVE — no sign correction unlike BLS12-381's negated-seed hard
/// part) a SHORT, FIXED number of times (three `f^x`-style applications
/// plus a handful of `Frobenius`/`conjugate`/`mul` combines — the exact
/// term-by-term formula is `finalExpHardPart`'s, below), using ONLY:
///   - `cyclotomicPow`-style exponentiation via `Fp12.cyclotomicSquare`
///     (ALREADY REAL, `fp12.zig` — see this file's module doc comment;
///     no new field-arithmetic primitive is needed for the hard part),
///   - `Fp12.frobeniusMap`/`Fp12.conjugate` (both ALREADY REAL,
///     `fp12.zig`) for the Frobenius-power and inversion-on-the-subgroup
///     steps (conjugation IS inversion on this subgroup — the identical
///     `p^6 ≡ -1 (mod p^4-p^2+1)` argument `bls12_381.finalExpHardPart`'s
///     doc comment spells out, curve-independent).
/// This pass pinned down the EXACT term ordering/exponent decomposition
/// (the Devegili-Scott-Dahab-lineage exact-`d` chain — NOT
/// Fuentes-Castañeda et al.'s, which computes a fixed power of `f^d`;
/// see `finalExpHardPart`'s doc comment for why) and re-verified it
/// NUMERICALLY against `(p^4-p^2+1)/r` with independent big-integer
/// arithmetic BEFORE trusting it — same discipline
/// `bls12_381.finalExpHardPart`'s own doc comment documents for its own
/// chain, and the exact discipline that makes a KAT harness like this
/// file's necessary in the first place (a plausible-but-wrong hard-part
/// chain is bilinearity-preserving in some cases yet still byte-wrong —
/// `bls12_381/README.md`'s own explicitly-cited cautionary precedent: "a
/// subtly-wrong f^(3d) final-exp chain was rejected by the byte-exact
/// KAT").
fn finalExponentiation(f: Fp12) Gt {
    return finalExpHardPart(finalExpEasyPart(f));
}

/// The "easy part": `f -> f^((p^6-1)(p^2+1))` — curve-generic,
/// transcribed verbatim from `bls12_381.pairing.finalExpEasyPart` per
/// `finalExponentiation`'s doc comment (the identities are `fp12.zig`'s
/// own documented ones: `f^(p^6-1) = conjugate(f)·f^-1` from
/// `Fp12.conjugate`'s doc comment, and `c^(p^2+1) = frobenius²(c)·c`
/// from `Fp12.cyclotomicSquare`'s day-one test oracle). `f.inv()` is
/// total here — a well-formed Miller-loop output is always a unit of
/// `Fp12*` (see the doc comment above; same `catch unreachable`
/// reasoning as `bls12_381`'s).
fn finalExpEasyPart(f: Fp12) Fp12 {
    // f^(p^6-1) = conjugate(f) * f^-1.
    const c = f.conjugate().mul(f.inv() catch unreachable);
    // c^(p^2+1) = frobenius^2(c) * c — result lands in the cyclotomic
    // subgroup (order dividing p^4-p^2+1), cyclotomicSquare's precondition.
    return c.frobenius().frobenius().mul(c);
}

/// The BN-specific "hard part": raises the easy part's output `m` (in
/// the order-`(p^4-p^2+1)` cyclotomic subgroup) to the EXACT power
/// `d = (p^4-p^2+1)/r`, landing the final result in `Gt`.
///
/// Construction — the Scott-Benger-Charlemagne-Perez-Kachisa (ePrint
/// 2008/490 §7) vectorial addition chain for the BN family's exact-`d`
/// base-`p` decomposition (the Devegili-Scott-Dahab 2007 §4 lineage
/// `finalExponentiation`'s doc comment cites; also the exact chain
/// Beuchat et al., "High-Speed Software Implementation of the Optimal
/// Ate Pairing over Barreto-Naehrig Curves", Pairing 2010, implement).
/// The Fuentes-Castañeda-Knapp-Rodríguez-Henríquez SAC 2011 chain the
/// doc comment names as the "more commonly-implemented" alternative was
/// deliberately NOT used: it computes a fixed nontrivial POWER of `f^d`
/// (bilinearity-equivalent, byte-DIFFERENT) and would fail this file's
/// byte-exact py_ecc KAT — the exact same reason `bls12_381
/// .finalExpHardPart` rejected it for its own KAT (that module's
/// documented cautionary precedent).
///
/// Chain (three seed exponentiations `m^x` — `x = bn_x`, POSITIVE, so
/// no sign-correcting conjugation unlike BLS12-381's negated seed — plus
/// Frobenius/conjugate/mul combines; conjugation IS inversion on this
/// subgroup, `p^6 ≡ -1 (mod p^4-p^2+1)`):
/// ```
/// y0 = m^p · m^(p²) · m^(p³)       y4 = (m^x · (m^(x²))^p)^-1
/// y1 = m^-1                        y5 = (m^(x²))^-1
/// y2 = (m^(x²))^(p²)               y6 = (m^(x³) · (m^(x³))^p)^-1
/// y3 = ((m^x)^p)^-1
/// t0 = y6² · y4 · y5;  t1 = y3 · y5 · t0;  t0 = t0 · y2
/// t1 = (t1² · t0)²;    t0 = t1 · y1;       t1 = t1 · y0
/// result = t0² · t1
/// ```
/// **Re-verified NUMERICALLY before being trusted** (the discipline this
/// function's contract demands): the chain's exponent, expanded with
/// independent big-integer arithmetic over the actual BN254 `p`/`r`/`x`
/// values, equals `(p^4-p^2+1)/r` EXACTLY as an integer (not merely mod
/// the subgroup order) — so this computes `f^d` itself, byte-identical
/// to py_ecc's plain `f^((p^12-1)/r)` oracle, which the KAT vectors
/// below then confirmed end-to-end. Cost: 3 `cyclotomicPowX` (64
/// cyclotomic squarings each) + 4 more cyclotomic squarings + 7
/// `frobeniusMap` calls + 12 `Fp12.mul` + 5 conjugations.
fn finalExpHardPart(m: Fp12) Fp12 {
    const mp = m.frobeniusMap(1);
    const mp2 = m.frobeniusMap(2);
    const mp3 = m.frobeniusMap(3);

    const mx = cyclotomicPowX(m);
    const mx2 = cyclotomicPowX(mx);
    const mx3 = cyclotomicPowX(mx2);

    const y0 = mp.mul(mp2).mul(mp3);
    const y1 = m.conjugate();
    const y2 = mx2.frobeniusMap(2);
    const y3 = mx.frobeniusMap(1).conjugate();
    const y4 = mx.mul(mx2.frobeniusMap(1)).conjugate();
    const y5 = mx2.conjugate();
    const y6 = mx3.mul(mx3.frobeniusMap(1)).conjugate();

    var t0 = y6.cyclotomicSquare().mul(y4).mul(y5);
    var t1 = y3.mul(y5).mul(t0);
    t0 = t0.mul(y2);
    t1 = t1.cyclotomicSquare().mul(t0).cyclotomicSquare();
    t0 = t1.mul(y1);
    t1 = t1.mul(y0);
    t0 = t0.cyclotomicSquare();
    return t0.mul(t1);
}

/// `f^e` for `f` in the CYCLOTOMIC subgroup, `e` a big-endian PUBLIC
/// byte string — square-and-multiply with `Fp12.cyclotomicSquare` for
/// every doubling (the hard part's whole speed point; the subgroup
/// precondition is exactly `cyclotomicSquare`'s own). Variable-time in
/// the exponent bits: the only exponent is the fixed public seed `x`
/// (`cyclotomicPowX`), same policy as `Fp2.pow`. Same shape as
/// `bls12_381.pairing.cyclotomicPow`.
fn cyclotomicPow(f: Fp12, e: []const u8) Fp12 {
    var acc = Fp12.one;
    for (e) |byte| {
        var bit: u3 = 7;
        while (true) : (bit -= 1) {
            acc = acc.cyclotomicSquare();
            if ((byte >> bit) & 1 == 1) acc = acc.mul(f);
            if (bit == 0) break;
        }
    }
    return acc;
}

/// `f^x` for `f` in the cyclotomic subgroup, `x` the BN seed (`bn_x`) —
/// POSITIVE, so unlike `bls12_381.cyclotomicExpSeed` there is NO
/// trailing conjugation (the sign-correction difference both this
/// file's module doc comment and `bn_x`'s own call out).
fn cyclotomicPowX(f: Fp12) Fp12 {
    var e: [8]u8 = undefined;
    std.mem.writeInt(u64, &e, bn_x, .big);
    return cyclotomicPow(f, &e);
}

// ── the pairing, and its batch/check forms (all REAL wiring) ───────────────

/// The BN254 optimal ate pairing `e(p, q)`: `finalExponentiation` composed
/// with the single-pair Miller loop, routed through `multiMillerLoop` (so
/// it inherits that function's infinity special-case for free) — the
/// module's primary single-pair entry point.
pub fn pairing(p: g1.Affine, q: g2.Affine) Gt {
    return finalExponentiation(multiMillerLoop(&.{.{ .p = p, .q = q }}));
}

/// The batch/aggregate pairing-product check a future Groth16 verifier
/// (Part 6, `README.md`) and EIP-197's `ecPairing` precompile semantics
/// (Part 5) both actually want: `true` iff `∏ e(p_i, q_i) == 1` over every
/// pair in `pairs` — WITHOUT ever materializing the individual `e(p_i,
/// q_i)` values or paying for more than ONE final exponentiation. REAL
/// wiring, same construction as `bls12_381.pairing.pairingCheck`:
/// `multiMillerLoop` already accumulates the product of every pair's raw
/// Miller value into one `Fp12`; `finalExponentiation` is a group
/// homomorphism on `Fp12*`, so ONE call over the accumulated product
/// equals the product of `N` separate final exponentiations.
pub fn pairingCheck(pairs: []const PairingPair) bool {
    return finalExponentiation(multiMillerLoop(pairs)).eql(Fp12.one);
}

// ── tests ────────────────────────────────────────────────────────────────
//
// Two tiers, a split inherited from the scaffold era (when the two cores
// were stubs — the split is kept because it documents which tests carry
// their own weight independent of the pairing core):
//
//   UNGATED (were real even pre-core): type/constant shape checks,
//   bn_ate_loop_param's comptime-derivation KAT, multiMillerLoop's
//   infinity-skip wiring (which never touches millerLoop for an
//   all-infinity input), and every pinned KAT hex vector's OWN
//   byte-parse/round-trip (proves the vectors themselves are well-formed
//   Fp12 encodings, independent of the core producing them).
//
//   GATED (`if (!gate.pairing_core_implemented) return error.SkipZigTest;`,
//   same pattern as `df-elect/src/protocol.zig`): every test that drives
//   `pairing`/`pairingCheck`/`finalExponentiation`/`multiMillerLoop` on a
//   non-all-infinity input — bilinearity, non-degeneracy, the
//   `pairingCheck` identities, and the byte-exact KAT comparisons
//   themselves. These SKIPPED until `gate.zig` flipped; with the core
//   real and the gate `true`, all of them now RUN.

fn g1Gen() g1.Jacobian {
    return g1.Jacobian.fromAffine(g1.Affine.generator);
}

fn g2Gen() g2.Jacobian {
    return g2.Jacobian.fromAffine(g2.Affine.generator);
}

test "Gt is Fp12 (documented convention, not a distinct type)" {
    try std.testing.expectEqual(Fp12, Gt);
}

test "PairingPair holds a (G1.Affine, G2.Affine) pair" {
    const pair: PairingPair = .{ .p = g1.Affine.generator, .q = g2.Affine.generator };
    try std.testing.expect(pair.p.x.eql(g1.Affine.generator.x));
    try std.testing.expect(pair.q.x.eql(g2.Affine.generator.x));
}

test "bn_x matches the documented BN254 seed (same value fp.zig/scalar.zig cite)" {
    try std.testing.expectEqual(@as(u64, 4965661367192848881), bn_x);
}

test "KAT: bn_ate_loop_param (6x+2) matches the independently-published ate_loop_count" {
    // py_ecc.bn128.bn128_pairing.ate_loop_count = 29793968203157093288
    // (independently confirmed via 6*4965661367192848881+2 outside this
    // module too — see SPEC.md's "Part 4 — KAT generation"). Comptime
    // -derived here from bn_x, not transcribed as a standalone literal.
    try std.testing.expectEqual(@as(u128, 29793968203157093288), bn_ate_loop_param);
}

test "multiMillerLoop of an empty slice is Fp12.one (no core call, no panic)" {
    try std.testing.expect(multiMillerLoop(&.{}).eql(Fp12.one));
}

test "multiMillerLoop never touches the stub on an all-infinity input (no panic, gate irrelevant)" {
    const result = multiMillerLoop(&.{
        .{ .p = g1.Affine.identity, .q = g2.Affine.generator },
        .{ .p = g1.Affine.generator, .q = g2.Affine.identity },
        .{ .p = g1.Affine.identity, .q = g2.Affine.identity },
    });
    try std.testing.expect(result.eql(Fp12.one));
}

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(1_000_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// KAT vectors: e(G1.generator, G2.generator) and two bilinear cross-checks,
// byte-exact in this module's own Fp12.toBytes wire order (c1||c0 through
// the tower, i.e. Fp6(c2||c1||c0) of Fp2(c1||c0) of Fp, high-to-low
// throughout). SOURCE: ethereum/py_ecc's `bn128` module (independently
// authored reference implementation), converted from its flat Fp12
// representation into this module's tower via a hand-derived isomorphism
// (both towers share w^6 = xi = 9+u by construction) that was validated as
// a ring homomorphism on 20 random Fp12 products before use — see this
// file's own module doc comment ("KAT sourcing") and SPEC.md's "Part 4 —
// KAT generation" for the full derivation and the validation script. The
// G1/G2 generator coordinates py_ecc used were confirmed byte-identical to
// this module's own g1.zig/g2.zig generators before computing these
// vectors.
const e_g1_g2_hex =
    "108c19d15f9446f744d0f110405d3856d6cc3bda6c4d537663729f5257628417" ++ // c1.c2.c1
    "0dc26f240656bbe2029bd441d77c221f0ba4c70c94b29b5f17f0f6d08745a069" ++ // c1.c2.c0
    "279db296f9d479292532c7c493d8e0722b6efae42158387564889c79fc038ee3" ++ // c1.c1.c1
    "1ad9db1937fd72f4ac462173d31d3d6117411fa48dba8d499d762b47edb3b54a" ++ // c1.c1.c0
    "27ed208e7a0b55ae6e710bbfbd2fd922669c026360e37cc5b2ab862411536104" ++ // c1.c0.c1
    "2c53748bcd21a7c038fb30ddc8ac3bf0af25d7859cfbc12c30c866276c565909" ++ // c1.c0.c0
    "2b03614464f04dd772d86df88674c270ffc8747ea13e72da95e3594468f222c4" ++ // c0.c2.c1
    "01676555de427abc409c4a394bc5426886302996919d4bf4bdd02236e14b3636" ++ // c0.c2.c0
    "2067586885c3318eeffa1938c754fe3c60224ee5ae15e66af6b5104c47c8c5d8" ++ // c0.c1.c1
    "0e841c2ac18a4003ac9326b9558380e0bc27fdd375e3605f96b819a358d34bde" ++ // c0.c1.c0
    "084f330485b09e866bc2f2ea2b897394deaf3f12aa31f28cb0552990967d4704" ++ // c0.c0.c1
    "12c70e90e12b7874510cd1707e8856f71bf7f61d72631e268fca81000db9a1f5"; //   c0.c0.c0

// e([2]G1, G2) — ALSO byte-identical to e(G1, [2]G2) (pinned as a single
// shared constant, exercised against both call shapes below): a stronger
// oracle than either alone, since it catches a Miller-loop bug specific to
// G1-side vs G2-side scalar handling that a same-value coincidence could
// otherwise mask.
const e_2g1_g2_hex =
    "12ce4a84c5d30fc882a51065b79455cd2c01e29892186f5697ff10a484966dd8" ++ // c1.c2.c1
    "0978f9c689049060d2441cce18feb66396bb4298659c1a31bc814969f5fc5b90" ++ // c1.c2.c0
    "24b2b9a39aa6b15b02ce71ebf986b9abbdc8bd47f788e15855d24d4053bcf74b" ++ // c1.c1.c1
    "0a64e97f95cc41ee3fc0fbefe6f2b059910545da941b1c8a89aee8f02e169f43" ++ // c1.c1.c0
    "049751ae000547ed967b817967fdb35ebcbd68e4e469c8d9c018512e5d759368" ++ // c1.c0.c1
    "025cf784d0c93c97d4f50fc9ebbcffbb84332897a083c16b82761bc5af9224ec" ++ // c1.c0.c0
    "0a82c549fcf23343b429bb0460fabbe211bea505117a8cc3946cc6bb872c71c8" ++ // c0.c2.c1
    "04d2c659c2ca171c272cb7c8a3a1f800c2b6cc46a8a2bca103421e8dfead2e4e" ++ // c0.c2.c0
    "1602f193b97bc449868e6a78dd5539523926c054e1dc3e3e7373a4e064fc66f4" ++ // c0.c1.c1
    "19c5de049b25274b99fcb2eff441b4a31de69c2e9ae6f96c73015c586e02767c" ++ // c0.c1.c0
    "258559fa8c9be5c20a6ee97e23fc9919089d205eabac1b8e83649cffb3b701ee" ++ // c0.c0.c1
    "2022b18414fce49209040b9bedd6b78ac240e8f66b604162b74da46879c95362"; //   c0.c0.c0

// e([3]G1, G2) — a third, independent byte-exact vector (different scalar
// than the doubling case above), so a formula error that happens to
// cancel at k=2 (e.g. a sign flip in an even-only code path) is still
// caught.
const e_3g1_g2_hex =
    "22a2ec54adfb7fe505bdf4f20a83559eae6f20f3810f96a1347700f7802716e0" ++ // c1.c2.c1
    "2e4a94cd0d64bc553d5a09bfaeccd16ca94d1589d9af30b8a5ce9d7e262ea1ad" ++ // c1.c2.c0
    "2e01011e4248797b2e0fd2ea2a81f742b90b213e190ab202084d0aa0248e2a57" ++ // c1.c1.c1
    "0f9383274f4cd73c1d9a3bb42f18b1c24fabd59bcd20398468fae090f35136d9" ++ // c1.c1.c0
    "1e458678cdaeeb37f4918e74ad7b3fbc6d0af07bd23fb4ee5278e59e3f25e8e6" ++ // c1.c0.c1
    "184ced193b86e29e248af421cc3e7dbfeba1b318c87ac6a64744e80a5d339eff" ++ // c1.c0.c0
    "06786f45bd60300559e56e76cb066936e5783b74349080d3130ad4fcc2e150ae" ++ // c0.c2.c1
    "05751930c0e345098466d9e792a7a84d5dd44c67eca9451aebe96daaf17d204a" ++ // c0.c2.c0
    "1a82554e735707e839b96ecadfa62cffd79d6ede128f467ec67b82064c65085a" ++ // c0.c1.c1
    "2afdf30cda62dc9f444c264279f686132bdade9eaaa025fb6ac44025801aaa9f" ++ // c0.c1.c0
    "1820b529c8f9007014134837344129502ab4ccef3eb39bbace85d006b2d141c2" ++ // c0.c0.c1
    "05e15e076b0f5f8b2a0e3036c714297b4b0dc73b4ba81a72aec4ff3e3f6511cb"; //   c0.c0.c0

test "KAT vectors parse into well-formed Fp12 elements (round-trip through Fp12.toBytes; no pairing core needed)" {
    inline for (.{ e_g1_g2_hex, e_2g1_g2_hex, e_3g1_g2_hex }) |hex| {
        const bytes = hexBytes(Fp12.encoded_bytes, hex);
        const el = try Fp12.fromBytes(bytes);
        try std.testing.expectEqualSlices(u8, &bytes, &el.toBytes());
    }
}

test "KAT: pairing(G1, G2) matches the independent py_ecc-derived e(G1,G2) vector" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const expected = hexBytes(Fp12.encoded_bytes, e_g1_g2_hex);
    const e = pairing(g1.Affine.generator, g2.Affine.generator);
    try std.testing.expectEqualSlices(u8, &expected, &e.toBytes());
}

test "KAT: pairing([2]G1, G2) matches the pinned e([2]G1,G2) vector" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p2 = g1Gen().double().toAffine();
    const expected = hexBytes(Fp12.encoded_bytes, e_2g1_g2_hex);
    const e = pairing(p2, g2.Affine.generator);
    try std.testing.expectEqualSlices(u8, &expected, &e.toBytes());
}

test "KAT: pairing(G1, [2]G2) matches the SAME pinned vector (G1-side/G2-side symmetry)" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const q2 = g2Gen().double().toAffine();
    const expected = hexBytes(Fp12.encoded_bytes, e_2g1_g2_hex);
    const e = pairing(g1.Affine.generator, q2);
    try std.testing.expectEqualSlices(u8, &expected, &e.toBytes());
}

test "KAT: pairing([3]G1, G2) matches the pinned e([3]G1,G2) vector" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p3 = g1Gen().double().add(g1Gen()).toAffine();
    const expected = hexBytes(Fp12.encoded_bytes, e_3g1_g2_hex);
    const e = pairing(p3, g2.Affine.generator);
    try std.testing.expectEqualSlices(u8, &expected, &e.toBytes());
}

test "pairing non-degeneracy: e(G1, G2) != 1" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const e = pairing(g1.Affine.generator, g2.Affine.generator);
    try std.testing.expect(!e.eql(Fp12.one));
}

test "final exponentiation lands in the order-r subgroup: e(G1,G2)^r == 1" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const e = pairing(g1.Affine.generator, g2.Affine.generator);
    const scalar_mod = @import("scalar.zig");
    try std.testing.expect(powBig(e, &scalar_mod.r_bytes).eql(Fp12.one));
}

test "pairing bilinearity: e([a]P, [b]Q) == e(P,Q)^(a*b) for small a=3, b=5" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p3 = g1Gen().double().add(g1Gen()).toAffine(); // [3]G1
    const q5 = g2Gen().double().double().add(g2Gen()).toAffine(); // [5]G2
    const lhs = pairing(p3, q5);
    const base = pairing(g1.Affine.generator, g2.Affine.generator);
    const rhs = powSmall(base, 15); // a*b = 15
    try std.testing.expect(lhs.eql(rhs));
}

test "pairing additivity in G1: e(P1+P2, Q) == e(P1,Q) * e(P2,Q)" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p1 = g1.Affine.generator;
    const p2 = g1Gen().double().toAffine(); // [2]G1
    const sum = g1Gen().add(g1Gen().double()).toAffine(); // P1 + P2
    const q = g2.Affine.generator;

    const lhs = pairing(sum, q);
    const rhs = pairing(p1, q).mul(pairing(p2, q));
    try std.testing.expect(lhs.eql(rhs));
}

test "pairing additivity in G2: e(P, Q1+Q2) == e(P,Q1) * e(P,Q2)" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p = g1.Affine.generator;
    const q1 = g2.Affine.generator;
    const q2 = g2Gen().double().toAffine(); // [2]G2
    const sum = g2Gen().add(g2Gen().double()).toAffine(); // Q1 + Q2

    const lhs = pairing(p, sum);
    const rhs = pairing(p, q1).mul(pairing(p, q2));
    try std.testing.expect(lhs.eql(rhs));
}

test "pairingCheck identity: e(P,Q) * e(-P,Q) == 1 (the ecPairing / EIP-197 'true' shape)" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p = g1.Affine.generator;
    const neg_p = g1Gen().negate().toAffine();
    const q = g2.Affine.generator;

    try std.testing.expect(pairingCheck(&.{
        .{ .p = p, .q = q },
        .{ .p = neg_p, .q = q },
    }));
}

test "pairingCheck rejects a non-trivial product: e(P,Q)*e(P,Q) is not 1" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const p = g1.Affine.generator;
    const q = g2.Affine.generator;
    try std.testing.expect(!pairingCheck(&.{
        .{ .p = p, .q = q },
        .{ .p = p, .q = q },
    }));
}

test "pairingCheck accepts a 3-pair product that multiplies to 1" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    // e(P,Q) * e(P,Q) * e([-2]P,Q) == e([2]P,Q) * e([2]P,Q)^-1 == 1.
    const p = g1.Affine.generator;
    const q = g2.Affine.generator;
    const neg_2p = g1Gen().double().negate().toAffine();
    try std.testing.expect(pairingCheck(&.{
        .{ .p = p, .q = q },
        .{ .p = p, .q = q },
        .{ .p = neg_2p, .q = q },
    }));
}

test "pairing with either input at infinity is 1 (multiMillerLoop's real skip; finalExponentiation still gated)" {
    if (!gate.pairing_core_implemented) return error.SkipZigTest;
    const e1 = pairing(g1.Affine.identity, g2.Affine.generator);
    const e2 = pairing(g1.Affine.generator, g2.Affine.identity);
    try std.testing.expect(e1.eql(Fp12.one));
    try std.testing.expect(e2.eql(Fp12.one));
}

/// Small-exponent `Fp12` power, `base^n` for a small COMPTIME `n` — test
/// helper only, mirrors `bls12_381.pairing`'s identically-named helper.
fn powSmall(base: Fp12, comptime n: usize) Fp12 {
    var acc = Fp12.one;
    for (0..n) |_| acc = acc.mul(base);
    return acc;
}

/// General big-exponent `Fp12` power (square-and-multiply, VARIABLE-TIME
/// in the exponent — fine here, `e` is always a PUBLIC test constant like
/// `Fr`'s modulus `r`) — test helper only, mirrors `bls12_381.pairing`'s
/// identically-named helper.
fn powBig(a: Fp12, e: []const u8) Fp12 {
    var acc = Fp12.one;
    for (e) |byte| {
        var bit: u3 = 7;
        while (true) : (bit -= 1) {
            acc = acc.square();
            if ((byte >> bit) & 1 == 1) acc = acc.mul(a);
            if (bit == 0) break;
        }
    }
    return acc;
}
