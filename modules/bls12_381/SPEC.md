# bls12_381 — SPEC

BLS12-381: the pairing-friendly elliptic curve behind BLS signatures,
KZG commitments, and threshold-BLS — see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

## Purpose

Part 1 of a multi-part arc (`README.md`): the base field `Fp`, the
extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`, and the two
pairing groups `G1`/`G2` — everything the Part-2 pairing function
(`e: G1 x G2 -> Gt`), and every part built on top of it, needs as its
foundation. This module does NOT implement the pairing itself, hash-to-
curve, BLS signatures, KZG, or threshold BLS — those are later parts.

## Model-after + seed

- **Source of truth**: `draft-irtf-cfrg-pairing-friendly-curves` (the
  BLS12-381 parameter family) plus the ZCash/IETF BLS12-381
  point-serialization convention — see `NOTICE` for the full citation
  list and the independent re-derivation/verification performed on
  every embedded constant.
- **`Fp`/`Fr` ride on `std.crypto.ff.Modulus`/`Fe`** (`fp.zig`/
  `scalar.zig`): std's own constant-time, allocation-free Montgomery
  modular-arithmetic machinery for a fixed-width odd modulus. This
  module supplies the BLS12-381-specific modulus values and the
  field-arithmetic entry points on top; it does NOT reimplement
  big-integer or Montgomery arithmetic itself. `Fp` uses a 384-bit
  (48-byte) container for the 381-bit `p`; `Fr` uses a 256-bit
  (32-byte) container for the 255-bit `r`.
- **Design references for the field-tower arithmetic** (implemented by
  the crypto-core pass): Devegili–Ó hÉigeartaigh–Scott–Dahab's
  tower-field multiplication paper (`Fp6`/`Fp12` mul/square/inv), Adj &
  Rodriguez-Henriquez ePrint 2012/685 Alg. 9 (`Fp2.sqrt`, the complex
  method), and the Bernstein–Lange Explicit-Formulas Database
  (`add-2007-bl`/`dbl-2009-l` Jacobian point formulas) — see `NOTICE`
  for full citations. `zkcrypto/bls12_381`/`blst` remain UNREAD as
  source code; every formula was validated against
  independently-computed vectors instead (NOTICE's "Verification
  performed (crypto-core pass)").

## Design & invariants

- **All arithmetic implemented** (crypto-core pass, 2026-07-14): the
  scaffold's REAL/STUB split is resolved — every field and group
  operation is now real, with one deliberate exception:
  `Fp12.cyclotomicSquare` remains `@panic("TODO(part2)")` (a
  pairing-only fast path that lands with its sole consumer, the Part-2
  final exponentiation — see its doc comment for the day-one test
  oracle Part 2 can use).
- **Montgomery-storage decision (settled)**: `Fp`/`Fr` store values
  CANONICALLY (non-Montgomery) at rest; `std.crypto.ff` operations
  preserve the first operand's form, so canonical-in/canonical-out
  holds everywhere and `toBytes`/`fromBytes` need no conversion at the
  struct boundary. Cost: `mul`/`sq` convert in/out of Montgomery form
  internally (a few extra Montgomery multiplications per call).
  Persistent Montgomery storage is a deferred Part-2 (pairing hot
  path) optimization — see Backlog.
- **Frobenius coefficients: derived in code, never transcribed.**
  `Fp6`'s `γ_1 = ξ^((p-1)/3)` (and `γ_2 = γ_1²`) and `Fp12`'s
  `γ = ξ^((p-1)/6)` are computed via `Fp2.pow` with exponents derived
  at COMPTIME from the verified `p_bytes` (`fp.pExponentBytes`, which
  hard-fails the build if a division is inexact). Tests pin them two
  ways: definitionally (`frobenius(a) == a^p` computed with plain
  mul/square) and byte-exactly against independently-recomputed values
  (NOTICE). Coefficients are recomputed per `frobenius` call — cheap
  for Part 1; caching is a Part-2 optimization (Backlog).
- **`Fp2` non-residue convention: `u² = -1`.** Confirmed by
  independently checking the `G2` generator on-curve under exactly this
  convention (`NOTICE`'s "Verification performed"). A different
  non-residue choice would produce a self-consistent but DIFFERENT
  curve/pairing — every constant and formula throughout the tower
  (`Fp6`'s `v³ = u+1`, `Fp12`'s `w² = v`, `G2`'s generator, Part 2's
  eventual Frobenius coefficients) must stay consistent with this one
  choice.
- **The `Fp2` wire-order pitfall**: an `Fp2` element `c0 + c1*u`
  serializes `c1` (high) before `c0` (low) — the OPPOSITE of the
  natural reading order. `fp2.zig`'s `encoded_bytes` doc comment flags
  this explicitly; it is a well-known, easy-to-miss BLS12-381 interop
  bug across implementations (byte-swapping the two halves produces a
  different-but-parseable value that can pass shape checks and only
  fail — or, on unlucky input, not even fail — the on-curve check).
- **The G2 cofactor scaffold bug (found and fixed by the crypto-core
  pass).** The scaffold's `g2.zig` `cofactor_bytes` was derived with
  the QUADRATIC-twist trace formula `#E' = p² + 1 - t2` — which is
  actually the order of `E(Fp2)` (the original curve over `Fp2`), not
  of the SEXTIC twist `G2` lives on. Because `E(Fp2) ⊇ E(Fp) ⊇ G1`,
  that wrong order is ALSO divisible by `r`, so the scaffold's
  exact-division sanity check passed. Caught because `clearCofactor`
  built on it failed the behavioral test (`[r]([h2]P) != O` — a direct
  Lagrange violation for the claimed group order); corrected via the
  CM equation for sextic twists (`f² = (4p² - t2²)/3`, `#E' = p² + 1 -
  (t2 - 3f)/2`) and triple-verified — see `g2.zig`'s `cofactor_bytes`
  doc comment and `NOTICE`. Lesson recorded: an exact-division check
  alone cannot distinguish the twist's order from the curve's; a
  behavioral (Lagrange) test can.

## Threat model / limits

- **The BLS subgroup-check pitfall — this module's central threat.**
  `E(Fp)` (`G1`'s curve) and `E'(Fp2)` (`G2`'s twist) both have order
  `r * h` for a cofactor `h` much larger than 1 (`h1` ≈ 126 bits, `h2` ≈
  636 bits — `g1.zig`/`g2.zig`'s `cofactor_bytes`). A point that merely
  satisfies the curve equation (`isOnCurve`) is NOT necessarily in the
  order-`r` subgroup `G1`/`G2` a pairing or BLS signature scheme
  requires. Accepting an unchecked on-curve-but-wrong-subgroup point
  from an untrusted source (e.g. a deserialized public key or
  signature) is a REAL, historically-exploited class of BLS
  implementation bug — an attacker can submit a small-subgroup point
  and force a degenerate or predictable pairing result, potentially
  forging signatures or breaking aggregation soundness depending on the
  scheme built on top. Every wire-decode entry point in this module
  (`fromBytesUncompressed`/`fromBytesCompressed` for both `G1` and
  `G2`) checks `isOnCurve` but explicitly does NOT check
  `subgroupCheck` — that is a SEPARATE call callers crossing a trust
  boundary MUST make (documented in each decode function's doc
  comment). Whether a later part of this module's arc (e.g. Part 4's
  BLS verify) folds the subgroup check into its own point-parsing
  entry point, or requires callers to call it explicitly, is that
  part's own design decision — Part 1 only guarantees the primitive
  (`subgroupCheck`, currently a stub) exists and is documented.
- **Constant-time choices (as implemented).**
  - `Fp`/`Fr` `add`/`sub`/`neg`/`mul`/`square` delegate to
    `std.crypto.ff` — constant-time by construction.
  - `Fr.pow` uses ff's fully-constant-time `powWithEncodedExponent`
    (constant-time in base AND exponent); `Fr.inv` likewise (its
    exponent `r-2` is fixed/public, but the conservative variant costs
    nothing and the base is often secret — threshold shares). `Fp.inv`/
    `Fp.sqrt` use the PUBLIC-EXPONENT variant — the exponents (`p-2`,
    `(p+1)/4`) are fixed public constants, and ff remains constant-time
    with respect to the BASE either way.
  - `Fp2.pow` (and the test-local `Fp6`/`Fp12` pows) are square-and-
    multiply, VARIABLE-TIME in the exponent bits — used exclusively
    with fixed public exponents (sqrt exponents, Frobenius-coefficient
    exponents); documented on the function.
  - `Fp2.sqrt`/`recoverY`/`toAffine`/deserialization are public-input
    paths and may branch (they do: on QR-ness, the sort bit, and
    identity).
  - `G1`/`G2` `scalarMul`/`scalarMulBytes` are constant-time
    double-and-add-ALWAYS: one `double` + one complete `add` +
    `ctSelect` accumulator update per bit, no secret-dependent branch
    or memory access (only the scalar's LENGTH, static per call site,
    is visible). Point `add` is COMPLETE via branchless resolution:
    the general `add-2007-bl` result and `double(a)` are both fully
    computed, then the degenerate cases (identity operands, `P == Q`,
    `P == -Q`) are folded in with `ctSelect` masks — no branch on which
    case fired (the accumulator's state is secret-dependent inside
    scalarMul).
  - `ctSelect` (`Fp`, lifted componentwise to `Fp2` and points) is a
    byte-mask merge over canonical serializations — branch-free and
    index-free.
  - `Fp.random`/`Fr.random` rejection-sample (never reduce a same-width
    sample — the classic bias footgun for these field shapes).
  Verification-side operations on public data (subgroup checks of
  public points, decompression) do not need — and some do not get —
  constant time; a faster public-scalar `scalarMul` variant is a
  possible later addition if a hot public-input call site appears.
- **Out of scope for Part 1**: the pairing function itself (Miller
  loop, final exponentiation — `fp12.zig`'s `// TODO(part2)` markers),
  hash-to-curve (Part 3), and every downstream scheme (BLS signatures,
  KZG, threshold BLS — Parts 4-6). `Fp12`'s `cyclotomicSquare`
  signature is scaffolded but deliberately left `@panic("TODO(part2)")`
  by the crypto-core pass — it is pairing-specific and lands with its
  only consumer (its doc comment records a pairing-free test oracle
  Part 2 can use on day one).

## Verification

- **KAT/oracle vectors wired** (all pass — 94 tests):
  - `fp.zig`: `p` is odd and exactly 381 bits (`modulus.bits()`);
    `half_p_bytes` independently recomputed as `(p-1)>>1` via raw byte
    arithmetic; zero/one round-trips; canonical-boundary rejection;
    field identities (`a·a⁻¹ = 1`, `(a+b)² = a²+2ab+b²`,
    `sqrt(a²) ∈ {±a}`, `sqrt(-1) = null` since `p ≡ 3 mod 4`);
    `pExponentBytes` reproduces `half_p_bytes`; `random` round-trips.
  - `scalar.zig`: the mirror `Fr` set, plus `reduceWide` KATs (`r → 0`,
    `r+1 → 1`, canonical passthrough, and a byte-exact
    `(2^512 - 1) mod r` vector computed independently).
  - `fp2.zig`: Karatsuba mul pinned by `u·u = -1`,
    `(1+u)(1-u) = 2`; norm-trick inv; `mulByNonresidue ==` general mul
    by `ξ`; `frobenius` is an involution AND `== pow(p)`
    (definitional); `sqrt(a²) ∈ {±a}`, `sqrt(ξ) = null` (`ξ` is a
    non-residue — verified independently), both `sqrt` branches
    exercised.
  - `fp6.zig`/`fp12.zig`: ring identities; `v³ = ξ` and `w² = v`
    (the defining tower relations, checked through general mul);
    norm-trick inversions; `frobenius == pow(p)` (definitional — this
    single test would catch ANY Frobenius-coefficient error) and
    order-6/order-12 (+`frobenius⁶ == conjugate`) checks; the derived
    `γ` coefficients byte-match independently-recomputed constants.
  - `g1.zig`/`g2.zig`: generator serialization KATs (`97f1d3a7...`
    reproduced for `G1`); full group-law suite (identity/inverse/
    commutativity/associativity/`add-vs-double` consistency);
    scalar-mul edge cases and distributivity; **independent
    cross-check vectors** for `[2]G`, `[k]G`, `[2]G2`, `[k]G2`
    (computed with a from-scratch affine-coordinates implementation —
    different algorithm family, see `NOTICE`); `subgroupCheck` accepts
    the generators and REJECTS independently-verified non-subgroup
    curve points, which `clearCofactor` then repairs (this behavioral
    pair is what caught the scaffold's wrong `h2`); decompression
    round-trips with both sort-bit values plus a `NotOnCurve` reject
    vector; uncompressed round-trips through real Jacobian arithmetic.
  - `root.zig`: every `encoded_bytes` constant matches its documented
    wire width; the dark-tests aggregator lists every submodule (disk
    test-block count == runtime count == 94).
- **Green in both modes**: `zig build test-bls12_381` (Debug) and
  `zig build test-bls12_381 -Doptimize=ReleaseFast` both pass 94/94
  (ReleaseFast exercised deliberately — this repo has been bitten by
  Debug-only-green UB before). `zig fmt --check modules/bls12_381/` is
  clean.

## Status

**Part 1 COMPLETE (crypto-core pass, 2026-07-14).** All field-tower
and group arithmetic implemented and verified — see "Design &
invariants" for the settled design decisions (canonical storage,
derived Frobenius coefficients, branchless point arithmetic, the fixed
G2 cofactor) and "Verification" for the test inventory. The single
remaining stub is `Fp12.cyclotomicSquare` (`TODO(part2)`, by design).

### Backlog (deferred)

1. **Part 2** (the pairing: Miller loop + final exponentiation,
   including `Fp12.cyclotomicSquare` and the `// TODO(part2)` helpers
   `fp12.zig` calls out) — a separate task.
2. **The fast subgroup-check / cofactor-clearing paths** (Bowe's
   untwist-Frobenius-twist technique, cited in `NOTICE`) — the simple,
   always-correct `scalarMul`-by-order/cofactor forms are implemented;
   the fast paths are marked `TODO` at their call sites.
3. **Performance (Part-2 prerequisites)**: persistent Montgomery
   storage for `Fp`/`Fr` (currently canonical-at-rest — see the
   convention note in `fp.zig`), caching the `Fp6`/`Fp12` Frobenius
   coefficients (currently recomputed per call), and a fixed-window
   scalar multiplication (currently double-and-add-always).
4. **Optional API additions if consumers appear**: a variable-time
   public-scalar `scalarMul` for verification-side hot paths; a
   secret-exponent (ladder) `Fp2.pow`.
