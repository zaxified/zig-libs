# bls12_381 — SPEC

BLS12-381: the pairing-friendly elliptic curve behind BLS signatures,
KZG commitments, and threshold-BLS — see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

## Purpose

Parts 1-3 of a multi-part arc (`README.md`). Part 1: the base field `Fp`,
the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`, and the two
pairing groups `G1`/`G2` — everything the pairing function needs as its
foundation. Part 2 (`pairing.zig`): the pairing itself, `e: G1 x G2 ->
Gt`, `Gt ⊂ Fp12*` — the optimal ate Miller loop plus final
exponentiation. Part 3 (`hash_to_curve.zig`): RFC 9380 hash-to-curve
for `G1`/`G2` — the primitive BLS signatures (Part 4) use to hash a
message onto the curve. This module does NOT implement BLS signatures,
KZG, or threshold BLS — those are later parts.

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

## Part 2 design (the pairing — crypto-core pass DONE, 2026-07-14)

- **Construction: optimal ate pairing (Vercauteren 2010), BLS12 family.**
  The standard choice for BLS12 curves — the shortest known Miller loop
  for this embedding degree (`k=12`), keyed to the low-Hamming-weight
  seed `x = -0xd201000000010000` (same `bls_x_abs` this file's siblings
  already cite). `G2`'s sextic twist is D-TYPE (confirmed by `g2.zig`'s
  own `b' = 4(1+u)` curve-equation choice and the `u^2=-1` non-residue
  convention `SPEC.md`'s Part-1 section documents) — line evaluations
  use the D-type untwisting map (Costello-Lange-Naehrig 2010).
- **Miller loop (as implemented)**: per-pair `T` accumulators in AFFINE
  twist coordinates (chord/tangent slope explicit for the line
  function; one `Fp2.inv` per step — total, because the twist group's
  order `r*h2` is odd, so no 2-torsion, and `T == ±Q` is impossible
  for subgroup inputs; see the doc comments' non-degeneracy arguments).
  Lines are evaluated at the TWISTED image of `P` — off the untwisted
  line by a fixed `w^3` factor per line, which the final exponentiation
  provably kills (`(w^3)^((p^12-1)/r) = 1`, derivation in `lineEval`'s
  doc comment) — giving the sparse `c0.c0/c0.c1/c1.c1` ("014") shape,
  promoted to a dense `Fp12.mul` in the correctness-first baseline.
  Multi-pairing shares one seed-bit walk + one accumulator per batch of
  up to 8 pairs (fixed stack storage, allocation-free; the batch
  product is exact — squaring distributes — so batching only forgoes
  cross-batch shared squarings). The negative seed is handled by ONE
  final conjugation.
- **Final exponentiation hard part (as implemented)**: the
  Hayashida–Hayasaka–Teruya (ePrint 2020/875, BLS12 case) EXACT-`d`
  cyclotomic identity `d = (p^4-p^2+1)/r = k*(x+p)*(x^2+p^2-1) + 1`
  with `k = (x-1)^2/3` — chosen over the scaffold's FCKRH (ePrint
  2011/465) suggestion because FCKRH's chain computes `f^(3d)` (a fixed
  CUBE of the canonical pairing: bilinearity-equivalent, and
  `pairingCheck`-equivalent since `gcd(3,r)=1`, but NOT byte-equal to
  the IETF draft's `e(G1,G2)` test vector — verified numerically for
  this exact seed before choosing). `k` is comptime-derived from
  `bls_x_abs` (division-by-3 exactness enforced at comptime — no
  transcribed constant); the whole chain runs on
  `Fp12.cyclotomicSquare` (Granger–Scott, PKC 2010, via the `Fp4`
  decomposition) + `Fp12.frobeniusMap` (naive repeated `frobenius`) +
  conjugation-as-inversion (`p^6 ≡ -1 (mod p^4-p^2+1)`, verified
  numerically).
- **The negative-seed sign convention (a real cross-implementation
  difference, discovered by the KAT work)**: this module — like
  zkcrypto/blst and the IETF pairing-friendly-curves draft's official
  test vector — conjugates the Miller accumulator for the negative
  seed. `py_ecc` does NOT (its loop walks `|x|` with no adjustment), so
  py_ecc's `e(G1,G2)` is exactly the canonical value's CONJUGATE (= Gt
  inverse). Both are valid bilinear pairings; the IETF draft's is the
  canonical one this module pins byte-exactly, and the py_ecc
  relationship is itself pinned by a dedicated cross-check test.
- **Verification net**: the bilinearity property suite (needs no
  external constant: non-degeneracy, `e([a]P,[b]Q) == e(P,Q)^(ab)`,
  additivity both sides, `e([a]P,Q) == e(P,[a]Q)`, `pairingCheck`
  identities positive and negative, `e(G1,G2)^r == 1`) PLUS the
  byte-exact `e(G1,G2)` KAT from the IETF draft (primary) and py_ecc
  (conjugate cross-check) — the "property tests as the strong oracle,
  byte-exact KAT layered on top" pattern from `adaptor`/`spake2plus`,
  now with both layers in place.

## Part 3 design (hash-to-curve — COMPLETE, crypto-core pass 2026-07-14)

- **Suites**: `BLS12381G1_XMD:SHA-256_SSWU_RO_` (RFC 9380 §8.8.1) and
  `BLS12381G2_XMD:SHA-256_SSWU_RO_` (§8.8.2) — the two `hash_to_curve`
  random-oracle encodings. Construction, per §3: `hash_to_field(msg,
  2)` → `map_to_curve` each of the two field elements → add the two
  curve points → `clear_cofactor`. `encode_to_curve` (the cheaper,
  nonuniform one-element variant, suites
  `BLS12381G{1,2}_XMD:SHA-256_SSWU_NU_`) is also implemented
  (`encodeToCurveG1`/`encodeToCurveG2`) since it shares the same
  `map_to_curve`/`clear_cofactor` machinery at near-zero extra cost.
- **`map_to_curve`** (`mapToCurveG1`/`mapToCurveG2`): §6.6.3 Simplified
  SWU for `AB == 0` — `sswuG1`/`sswuG2` (§6.6.2's Simplified SWU proper,
  onto the isogenous curves `E1'`/`E2'`, using the new RFC-9380 `inv0`/
  `sgn0` helpers on `Fp`/`Fp2`) then `isogenyMap11`/`isogenyMap3` (the
  Appendix E.2/E.3 rational isogeny maps back onto `G1`/`G2`'s actual
  curves — Horner evaluation over the 53-/13-coefficient tables, monic
  leading denominator terms implicit, zero-denominator exceptional case
  → identity). The SSWU `tv1 == 0` exceptional branch's totality (its
  `g(B/(Z*A))` is always a QR, so the gx2 fallback never fails) was
  verified numerically — see `NOTICE`.
- **`clear_cofactor` = `h_eff` multiplication, NOT plain-cofactor
  multiplication — a scaffold-plan CORRECTION.** The scaffold planned to
  reuse Part 1's `clearCofactor` (multiply by the true cofactor `h`)
  and documented both as "valid per §7"; that is WRONG for these
  suites: §7 pins `clear_cofactor(P) := h_eff * P` (a fixed suite
  parameter, §8.8.1/§8.8.2) and explicitly says plain-`h` multiplication
  "does not generally give the same result ... and MUST NOT be used"
  when `h_eff` comes from a fast clearing method (both BLS12-381
  suites' do). Confirmed empirically: `[h]R != [h_eff]R` on the RFC's
  own vector points, both groups — same subgroup, different point, so
  the J.9.1/J.10.1 final-`P` KATs would fail with `h`. The compositions
  multiply by the suites' `h_eff` via `scalarMulBytes` (`NOTICE`
  entry 21); `g1`/`g2.Jacobian.clearCofactor` remains what it always
  was — a correct way to land arbitrary points in the subgroup — it
  just is not RFC 9380's `clear_cofactor`.
- **`expand_message_xmd` reuse decision (flagged, not unilateral)**:
  `modules/frost` and `modules/voprf` each already carry an in-module
  `expand_message_xmd`, but both are hardcoded to a fixed `ell`
  (frost: SHA-256/`ell=2`; voprf: SHA-512/`ell=1`) that is too narrow
  for this module's needs (`G1`'s `hash_to_field(msg,2)` needs `ell=4`;
  `G2`'s needs `ell=8`), and reusing either directly would add a
  cross-module dependency edge from `bls12_381` to a threshold-signature
  or OPRF module for one hash primitive — a layering smell. This pass
  REIMPLEMENTS `expand_message_xmd` from the RFC 9380 §5.3.1 pseudocode
  directly, generalized to any `ell <= 255` (frost's/voprf's versions
  are each a specialization of this general shape) — a deliberate,
  explicitly-flagged departure from a literal "reuse the existing
  implementation" instruction; the owner may instead choose to factor a
  shared `expand_message_xmd` helper across all three modules later,
  but that is a cross-module refactor this scaffolding pass does not
  make unilaterally.
- **The `Fp` wide-reduction gap**: `hash_to_field`'s `OS2IP(tv) mod p`
  step needs to reduce a 512-bit (`L=64`-byte) integer into `Fp`
  (384-bit container). `scalar.zig`'s `Fr.reduceWide` already solves the
  analogous problem for `Fr` (256-bit container, same 512-bit input)
  via `std.crypto.ff.Uint(512).fromBytes` + `modulus.reduce(wide)` (the
  latter generic in the input width). The identical construction works
  unchanged for `Fp` — confirmed by reading `std.crypto.ff`'s
  `Modulus.reduce` signature (`fn reduce(self: Self, x: anytype) Fe`) —
  so this is REAL, not stubbed; kept as a file-local
  `reduceWideToFp` in `hash_to_curve.zig` rather than promoted to a
  public `Fp.reduceWide` in `fp.zig` (unlike `Fr`'s), since
  `hash_to_field` is (so far) its only consumer — promote it if a
  second caller appears.
- **Constant provenance**: `g1_iso_z`/`g1_iso_a`/`g1_iso_b` and
  `g2_iso_z`/`g2_iso_a`/`g2_iso_b` (the SSWU curve/`Z` parameters for
  `E1'`/`E2'`) are single field-element constants cited verbatim from
  RFC 9380 §8.8.1/§8.8.2's own raw text (re-confirmed against that text
  during the crypto-core pass), the same citation discipline `fp.zig`'s
  `p_bytes`/`g1.zig`'s generator already use. The 11-isogeny (`G1`,
  Appendix E.2, 53 `Fp` constants) and 3-isogeny (`G2`, Appendix E.3,
  13 `Fp2` constants) coefficient tables were NEVER hand-transcribed:
  they were parsed programmatically from the RFC's raw text and emitted
  as Zig literals mechanically, then validated end-to-end by an
  independent big-integer implementation reproducing the RFC's own
  `Q0`/`Q1`/`P` vectors on exactly those parsed values — see `NOTICE`'s
  Part-3 crypto-core verification section. Every table entry is a
  comptime `Fp.fromBytes` (`fpc`/`fp2c`), so a wrong-length or
  non-canonical value fails the build outright. The suites' `h_eff`
  scalars (§8.8.1/§8.8.2) are likewise cited from the raw text
  (`NOTICE` entry 21).

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
- **The pairing is VARIABLE-TIME — deliberately.** Pairings operate on
  PUBLIC inputs (public keys, signatures, commitments — every
  BLS/KZG-style consumer verifies public data with them); the Miller
  loop's affine steps branch and invert on input-derived values, the
  final exponentiation's exponents are fixed public curve constants,
  and no constant-time contortion is attempted or needed. Do NOT feed
  the pairing secret points without revisiting this (no known scheme
  does). The pairing also assumes SUBGROUP inputs for its internal
  non-degeneracy arguments (the affine steps' `catch unreachable`
  inversions): an on-curve but small-order non-subgroup point could
  panic mid-loop — a loud failure, not a silent wrong value, and
  exactly the input class the module-wide subgroup-check obligation
  already excludes at trust boundaries.
- **Hash-to-curve is VARIABLE-TIME — deliberately, same reasoning as the
  pairing.** RFC 9380 hash-to-curve's input `msg` is, in every consumer
  this module anticipates (BLS message hashing, Part 4), PUBLIC — it is
  the message being signed/verified, never a secret. §6.6.2's Simplified
  SWU map branches on `is_square`/`sgn0` (data-dependent), and §6.6.3's
  isogeny map branches on its exceptional zero-denominator case; RFC
  9380 §10.3 itself only mandates constant-time behavior for
  password-hashing use cases (§10.2), which this module does not target.
  Do NOT feed `hash_to_curve`/`encode_to_curve` a secret message without
  revisiting this (no BLS/KZG/threshold-BLS consumer does).
- **Out of scope for Parts 1-3**: BLS signatures, KZG, threshold BLS
  (Parts 4-6). Also out of scope for Part 3 specifically: any suite
  other than the two `_XMD:SHA-256_SSWU_RO_`/`_NU_` pairs BLS12-381
  actually uses (e.g. `expand_message_xof`/SHAKE variants RFC 9380
  defines for other curves) — this module implements only the SHA-256
  `expand_message_xmd` variant.

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
    test-block count == runtime count == 112, Parts 1+2).
  - `fp12.zig` (Part-2 additions): `cyclotomicSquare == square` on a
    REAL cyclotomic-subgroup element (built pairing-free via the easy-
    part construction, iterated 3 steps) and on `one`;
    `frobeniusMap(k)` consistency for `k ∈ {0,1,2,3,6,12,13}`
    (including `frobeniusMap(6) == conjugate` and the mod-12
    reduction).
  - `pairing.zig` (Part 2 — ALL PASS): `Gt`/`PairingPair`/`bls_x_abs`
    sanity; `millerLoop` is definitionally `multiMillerLoop`'s `N=1`
    case; non-degeneracy (`e(G1,G2) != 1`); bilinearity
    (`e([3]P,[5]Q) == e(P,Q)^15`, additivity in both `G1` and `G2`,
    `e([7]P,Q) == e(P,[7]Q) == e(P,Q)^7`); the `pairingCheck` identity
    `e(P,Q)*e(-P,Q) == 1`, a 3-pair product-to-one check, and the
    negative (`pairingCheck` on a single non-trivial pair rejects);
    infinity-input handling (`e(O,Q) == e(P,O) == 1`, including inside
    a multi-pairing); final-exp subgroup-membership sanity
    (`e(G1,G2)^r == 1`); and the byte-exact `e(G1,G2)` KAT — the IETF
    draft-irtf-cfrg-pairing-friendly-curves-11 Appendix B optimal-ate
    vector (primary) plus the py_ecc-is-the-conjugate cross-check (see
    "Part 2 design" above).
- **Green in both modes (Parts 1-2)**: `zig build test-bls12_381`
  (Debug) and `zig build test-bls12_381 -Doptimize=ReleaseFast`
  (ReleaseFast — exercised deliberately, this repo has been bitten by
  Debug-only-green UB before) both report **112/112 tests pass, 0
  panics**. `zig fmt --check modules/bls12_381/` is clean.
- **Part 3 vectors (`hash_to_curve.zig` + the new `fp.zig`/`fp2.zig`
  helpers — ALL PASS)**: `expandMessageXmd` against RFC 9380
  **Appendix K.1** (`expand_message_xmd(SHA-256)`, DST
  `"QUUX-V01-CS02-with-expander-SHA256-128"`) for both published
  `len_in_bytes` values, `0x20` (`ell=1`) and `0x80` (`ell=4`), all 5
  messages each; `hashToFieldFp`/`hashToFieldFp2` against **Appendix
  J.9.1**/**J.10.1**'s `u[0]`/`u[1]` intermediates;
  `mapToCurveG1`/`mapToCurveG2` against J.9.1/J.10.1's **`Q0`/`Q1`**
  intermediates (localizing any bug to the SSWU+isogeny map, plus
  on-curve assertions); `hashToCurveG1`/`hashToCurveG2` against
  J.9.1/J.10.1's **final `P`** — all 5 messages each, byte-exact, so
  the entire chain (including the add + `h_eff` clear_cofactor tail)
  is pinned at every stage the RFC publishes. Property tests:
  `hashToCurve*`/`encodeToCurve*` outputs are on-curve AND pass
  `subgroupCheck` for arbitrary non-vector messages; `sswuG1`/`sswuG2`
  at `u = 0` exercise the `tv1 == 0` exceptional branch and land on
  `E1'`/`E2'` with `sgn0(y) == 0`; `Fp`/`Fp2` `inv0`/`sgn0` unit tests
  (including the `sgn0`-vs-`isLexicographicallyLargest` convention
  distinction). **Net: `zig build test-bls12_381` reports 128/128
  pass, 0 panics, in both Debug and ReleaseFast** (`zig fmt --check`
  clean; disk test-block count == runtime count == 128).

## Status

**Part 1 COMPLETE (crypto-core pass, 2026-07-14).** All field-tower
and group arithmetic implemented and verified — see "Design &
invariants" for the settled design decisions (canonical storage,
derived Frobenius coefficients, branchless point arithmetic, the fixed
G2 cofactor) and "Verification" for the test inventory.

**Part 2 COMPLETE (crypto-core pass, 2026-07-14).** `multiMillerLoop`
(optimal ate, affine D-type-twist line evaluation, allocation-free
batched multi-pairing), `finalExpHardPart` (Hayashida–Hayasaka–Teruya
exact-`d` cyclotomic chain), `Fp12.cyclotomicSquare` (Granger–Scott)
and `Fp12.frobeniusMap` (naive repeated Frobenius) are all real and
verified — bilinearity property suite plus the byte-exact IETF-draft
`e(G1,G2)` KAT with py_ecc conjugate cross-check. See "Part 2 design"
above for the algorithm choices and the FCKRH-vs-exact-`d` and
negative-seed-convention findings.

**Part 3 COMPLETE (crypto-core pass, 2026-07-14).** The full RFC 9380
chain — `expandMessageXmd` (§5.3.1, general `ell`), `hashToFieldFp`/
`hashToFieldFp2` (§5.2), `sswuG1`/`sswuG2` (§6.6.2 Simplified SWU, on
the new `Fp`/`Fp2` `inv0`/`sgn0` helpers), `isogenyMap11`/`isogenyMap3`
(§6.6.3 iso_map over the programmatically-sourced Appendix E.2/E.3
tables), and the `hashToCurve*`/`encodeToCurve*` compositions with
`h_eff`-based `clear_cofactor` — is implemented and byte-exact against
RFC 9380's own J.9.1/J.10.1 vectors at every published stage. See
"Part 3 design" above for the `expand_message_xmd`
reuse-vs-reimplement decision, the `Fp` wide-reduction finding, the
constant-provenance discipline, and the `h_eff`-vs-plain-cofactor
scaffold correction (the one place the scaffold's stated plan was
wrong).

### Backlog (deferred)

1. **The Miller-loop sparse-multiplication optimization** — a freshly
   computed line value is structurally sparse (3 nonzero `Fp2`
   coefficients out of 6 — the "014" shape `lineEval` documents); the
   implemented baseline promotes it to a dense `Fp12` and uses the
   general `mul`, correctness-first; a dedicated sparse-multiply is a
   real, well-known follow-up optimization (`multiMillerLoop`'s own
   `TODO` note), not a correctness prerequisite. Projective (inversion-
   free) Miller-loop point steps belong to the same future performance
   pass (the affine steps cost one `Fp2.inv` each — fine for
   verification workloads, the only current consumers).
2. **The fast subgroup-check / cofactor-clearing paths** (Bowe's
   untwist-Frobenius-twist technique, cited in `NOTICE`) — the simple,
   always-correct `scalarMul`-by-order/cofactor forms are implemented;
   the fast paths are marked `TODO` at their call sites.
3. **Performance**: persistent Montgomery storage for
   `Fp`/`Fr` (currently canonical-at-rest — see the convention note in
   `fp.zig`), caching the `Fp6`/`Fp12` Frobenius coefficients (currently
   recomputed per call — directly relevant to `Fp12.frobeniusMap`'s own
   deferred caching choice), and a fixed-window scalar
   multiplication (currently double-and-add-always).
4. **Optional API additions if consumers appear**: a variable-time
   public-scalar `scalarMul` for verification-side hot paths; a
   secret-exponent (ladder) `Fp2.pow`; skipping the full final
   exponentiation for `pairingCheck` specifically when a cheaper
   not-equal-to-one test suffices (`pairingCheck`'s own `TODO(fable)`
   note).
5. **Part 3 performance follow-ups** (correctness is DONE — see
   Status): the endomorphism-based FAST `clear_cofactor` evaluation
   (Scott [WB19] for `G1`, Budroni-Pintore [BP17]/Appendix G.3 for
   `G2`) — the current implementation multiplies by the same suite
   `h_eff` those methods are equivalent to, via the generic
   constant-time `scalarMulBytes` (`G2`'s 636-bit `h_eff` makes this
   the dominant hash-to-curve cost); §6.6.3's add-on-`E1'`-before-
   `iso_map` homomorphism trick (saves one isogeny evaluation per
   `hash_to_curve`); and a variable-time public-scalar multiplication
   for the `h_eff` step (hash-to-curve input is public — see the
   threat model).
