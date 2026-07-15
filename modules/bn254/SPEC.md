# bn254 — SPEC

BN254 (alt-bn128): see [README.md](README.md) for purpose and API.

## Purpose

The full 6-part arc (`README.md`) is now COMPLETE: the base field `Fp`,
the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`
(Parts 1-2), the pairing groups `G1`/`G2` (Part 3, `g1.zig`/`g2.zig`),
the optimal-ate pairing (Part 4, `pairing.zig`), the EIP-196/197 EVM
precompiles (Part 5, `precompiles.zig`), and a Groth16 zk-SNARK verifier
(Part 6, `groth16.zig`) — see "Part 4 — pairing", "Part 5 — EVM
precompiles", and "Part 6 — Groth16 verifier" below for each part's own
accounting.

## Model-after + seed

- **Source of truth for the field/curve parameters**: EIP-196
  (`https://eips.ethereum.org/EIPS/eip-196`) and EIP-197
  (`https://eips.ethereum.org/EIPS/eip-197`) — the Ethereum alt_bn128
  precompile specification — cross-checked against `py_ecc`'s
  published `bn128_field_elements.field_modulus` /
  `bn128_curve.curve_order` / `bn128_curve.G1` / `bn128_curve.G2`
  constants (these are PUBLISHED NUMBERS, not copyrightable expression
  — see the "NOTICE" section below for why no NOTICE entry is needed).
- **`Fp`/`Fr` ride on `std.crypto.ff.Modulus`/`Fe`** (`fp.zig`/
  `scalar.zig`), exactly as `bls12_381` does — this module supplies the
  BN254-specific modulus values and field-arithmetic entry points on
  top; it does NOT reimplement big-integer or Montgomery arithmetic
  itself. Both `Fp` and `Fr` use a 256-bit (32-byte) container — a
  BN254-specific quirk vs. `bls12_381` (whose `Fp`/`Fr` use DIFFERENT
  widths, 384 vs. 256 bits) because BN254's `p` and `r` are both
  exactly 254 bits.
- **The extension-tower ARITHMETIC (mul/square/inv formulas) is
  ADAPTED, not reinvented, from the sibling `bls12_381` module.** The
  Devegili–Ó hÉigeartaigh–Scott–Dahab tower-multiplication formulas
  (`Fp6`/`Fp12` mul/square/inv) and the Adj & Rodriguez-Henriquez
  ePrint 2012/685 Algorithm 9 complex-method square root (`Fp2.sqrt`)
  are GENERIC in the field's non-residue — every formula is expressed
  only through `mulByNonresidue`/`add`/`sub`/`mul` calls, never a
  literal non-residue constant baked into the algebra — so they carry
  over from `bls12_381` UNCHANGED; only the non-residue VALUES
  (`fp2.zig`'s `u²=-1` — same as `bls12_381`; `fp6.zig`'s `ξ=9+u` —
  DIFFERENT from `bls12_381`'s `ξ=u+1`) and the modulus `p` itself
  differ. `bls12_381`'s own SPEC.md records that these formula shapes
  were themselves validated against independently-computed vectors,
  not transcribed from `zkcrypto`/`blst` source — that provenance
  carries forward here.
- **Granger–Scott cyclotomic squaring** (`fp12.zig`'s
  `cyclotomicSquare`, "Faster Squaring in the Cyclotomic Subgroup of
  Sixth Degree Extensions", PKC 2010) is likewise generic in the
  tower's non-residues and copied unchanged from `bls12_381`.
- **Part 3's `G1`/`G2` Jacobian point arithmetic (`add`/`double`,
  add-2007-bl/dbl-2009-l, Bernstein–Lange EFD `shortw/jacobian-0`) is
  ADAPTED unchanged from `bls12_381/src/g1.zig`/`g2.zig`** — both
  formulas are GENERIC in the curve's `b` constant (only the `a = 0`
  short-Weierstrass coefficient matters, which BN254's `G1`/twist `E'`
  share with BLS12-381's), so only the curve constants (`b = 3` for
  `G1`; `b' = 3*(9+u)^-1` for `G2`'s twist) and generator coordinates
  differ. `G1`'s wire codec is a NEW, simpler design vs.
  `bls12_381/src/g1.zig`'s (EIP-196/197 has no compressed format or
  flag bits, unlike the ZCash/IETF format `bls12_381` uses) — see
  `g1.zig`/`g2.zig`'s module doc comments for the exact reasoning.

## Design & invariants

- **`p ≡ 3 (mod 4)`, `p ≡ 1 (mod 3)`, `p ≡ 1 (mod 6)`** — all three
  confirmed directly from `p_bytes` and independently in Python (see
  "Verification performed" below). These are exactly the congruences
  every formula in this tower depends on (`Fp.sqrt`'s simple case,
  `Fp2.sqrt`'s complex method, `Fp6`/`Fp12`'s exact-division Frobenius
  exponents) — same congruence class as `bls12_381`'s `p`, which is why
  the formula shapes transfer without modification.
- **Frobenius coefficients: derived in code, never transcribed** — same
  discipline as `bls12_381`. `Fp6`'s `γ_1 = ξ^((p-1)/3)` (`γ_2 =
  γ_1²`) and `Fp12`'s `γ = ξ^((p-1)/6)` are computed via `Fp2.pow` with
  exponents derived at COMPTIME from the verified `p_bytes`
  (`fp.pExponentBytes`, which hard-fails the build if a division is
  inexact). Pinned two ways: definitionally (`frobenius(a) == a^p`
  computed with plain mul/square) and byte-exactly against
  independently-recomputed values (see KAT tests in `fp6.zig`/
  `fp12.zig`).
- **`Fp2` non-residue convention: `u² = -1`.** SAME as `bls12_381` —
  confirmed independently: `py_ecc.bn128`'s `FQ2` uses
  `modulus_coeffs = (1, 0)`, i.e. `i² + 1 = 0`.
- **`Fp6` non-residue convention: `ξ = 9 + u`.** DIFFERENT from
  `bls12_381`'s `ξ = u+1` — this is the standard BN254 tower
  construction (confirmed via the `G2`-twist on-curve check below: the
  twist coefficient `b₂ = 3/ξ` only lands on the known-published `G2`
  generator with `ξ = 9+u`).
- **No `isLexicographicallyLargest` (deliberate omission vs.
  `bls12_381`).** `bls12_381` needs this "sign of y" helper because its
  point-serialization convention (ZCash/IETF) COMPRESSES points (x-only
  + a 1-bit sign flag). Ethereum's EIP-196/197 `G1`/`G2` precompile
  encoding is UNCOMPRESSED — raw `(x, y)` (and `(x_im, x_re, y_im,
  y_re)` for `G2`) coordinate pairs, no compression, no sign bit. This
  module therefore has no correctness need for that helper in its
  planned arc; adding it back is a one-line change if a future
  compressed-encoding consumer ever appears, but it would currently be
  dead, untested code.
- **Montgomery-storage / canonical-storage convention: identical to
  `bls12_381`** (`Fp`/`Fr` store canonically at rest; see `fp.zig`'s
  module doc comment).
- **`G1`'s cofactor is 1 — a load-bearing fact, not a simplification.**
  BN254's defining polynomial family gives `#E(Fp) = p + 1 - t = r`
  EXACTLY (`t = 6x^2+1`, confirmed `p + 1 - t == r` symbolically — see
  "Verification performed" below), i.e. `r` (prime) IS the full order
  of `E(Fp)`, not merely a large prime factor. Since a group of prime
  order has no nontrivial proper subgroups, `E(Fp)` and `G1` are THE
  SAME SET — `isOnCurve() == subgroupCheck()` for every point,
  unconditionally. This is a REAL difference from `bls12_381`'s `G1`
  (cofactor `h1 = 0x396c8c...`, nontrivial), not a shortcut this module
  took: `g1.zig`'s `subgroupCheck` returning `isOnCurve()` is the
  mathematically exact answer, verified independently two ways (the
  polynomial identity, and `[r]G1 == O` computed via full scalar-mul in
  both this module's tests and the Python cross-check below).
- **`G2`'s cofactor is NONTRIVIAL** (`#E'(Fp2) = r * h2`, `h2 > 1`) —
  `subgroupCheck` for `G2` is a REAL `[r]P == O` scalar multiplication
  (`g2.zig`), not a shortcut. This module does NOT compute or expose
  `h2`/cofactor-clearing: BN254 has no standardized hash-to-`G2` used by
  EIP-197 precompile semantics or Groth16 verification (both only ever
  consume caller-supplied `G2` points, never hash an arbitrary message
  onto the twist), so cofactor clearing has no consumer in this arc —
  see `g2.zig`'s module doc comment. `subgroupCheck` alone (no
  clearing) is sufficient and IS exercised: a constructed on-twist,
  non-subgroup point (`x = u`) is verified to FAIL it (see `g2.zig`'s
  tests and "Verification performed" below).
- **`b' = 3/ξ = 3*(9+u)^-1` is DERIVED at runtime via real `Fp2`
  arithmetic (`g2.zig`'s `twistB()`), never hand-transcribed as a
  numeric literal.** Pinned byte-exact against an independent Python
  computation (below).
- **EIP-197's `G2` wire encoding is imaginary-component-FIRST**: an
  `Fp2` element `a + b*i` serializes as `(b, a)`. Combined with `Fp2`'s
  `c1` being the `u`-coefficient (`fp2.zig`'s convention), the 128-byte
  `G2` encoding is `x.c1 || x.c0 || y.c1 || y.c0` — see `g2.zig`'s codec
  section doc comment. Pinned against a KAT vector where `c0 != c1` on
  every coordinate (the generator itself qualifies), so a swapped
  ordering could not silently pass.

## Tier assessment — Fable NOT required for Parts 1-3

This is a **careful, verified ADAPTATION**, not novel cryptographic
design. Every algorithm (Montgomery field arithmetic via
`std.crypto.ff`, Karatsuba/Devegili tower multiplication, the
Adj–Rodriguez-Henriquez complex-method square root, Granger–Scott
cyclotomic squaring, programmatic Frobenius-coefficient derivation) is
the SAME formula shape already proven correct and battle-tested in the
sibling `bls12_381` module — the only things that changed are the
modulus `p`/`r` and the `Fp6` non-residue `ξ`, both independently
verified against multiple public sources (below) and pinned by
byte-exact KAT. Nothing here required inventing a new algorithm,
resolving an ambiguous spec, or making an irreducible cryptographic
design judgment call. **No stub was left; no test was weakened to
pass; every identity (Fermat, Frobenius=pow(p), cyclotomic-square=
square-on-subgroup, ring axioms) held on the first implementation
attempt** — there was no "genuinely subtle" failure to isolate.

**Part 3 (`G1`/`G2`) is the same story, one level up.** The Jacobian
`add`/`double` formulas are UNCHANGED from `bls12_381` (generic in `b`);
`scalarMul`'s constant-time double-and-add-always construction is
UNCHANGED. The two genuinely BN254-specific pieces — `G1`'s cofactor
being exactly 1 (not merely "small"), and deriving `b' = 3/(9+u)` in
`Fp2` rather than transcribing it — are ARITHMETIC FACTS with a
mechanical derivation and an independent Python cross-check each, not
open design questions: there was no ambiguity about which of two
candidate formulas to use, no judgment call about a threat model, no
place a wrong choice could have been made and only discovered by an
adversarial audit. Every group-law identity (associativity,
distributivity of `scalarMul`, `[r]G1 == O`, `[r]G2 == O`, the
non-subgroup `G2` point failing `subgroupCheck`, every `[k]G`
byte-exact KAT) passed on the first implementation attempt — again, no
"genuinely subtle" failure surfaced. The Fable-hard work in this arc is
Part 4's pairing core (`millerLoop`/`finalExponentiation`) — this IS
where BN254 diverges non-trivially from BLS12-381 (a different `6x+2`
(not `|x|`) loop parameter, the BN-specific Frobenius-tail addition
steps, and a different final-exponentiation hard-part addition chain —
see "Part 4 — pairing" above). Part 4's SCAFFOLD (the type
shapes, the KAT harness, the real infinity/composition wiring) was,
like Parts 1-3, a careful, verified adaptation of `bls12_381/src
/pairing.zig`'s structure — no design judgment call was needed for the
scaffold itself. The two irreducible cores were the genuinely
harder-tier work: a dedicated Fable crypto-core pass implemented them
(and caught a real BN-vs-BLS untwist/line-slot subtlety only the
byte-exact KAT surfaced — see "Part 4 — pairing" below).

## Part 4 — pairing

`pairing.zig` implements the optimal-ate pairing `e: G1 x G2 -> Gt`
(`Gt` = the order-`r` cyclotomic subgroup of `Fp12*`) — COMPLETE: every
structural piece plus both irreducible crypto-core functions
(`millerLoop`, `finalExponentiation`) are implemented and tested,
byte-exact against `py_ecc`. The type shapes / KAT harness / wiring
were a careful adaptation of `bls12_381/src/pairing.zig`'s structure
(scaffold pass); the two cores were a dedicated Fable crypto-core pass
— see `NOTICE`'s "Verification performed" for the tier reasoning.

**Structural pieces (adapted from `bls12_381`, scaffold pass):**
- `Gt` (= `Fp12`, the "trust the constructor" convention already used by
  `bls12_381.pairing.Gt`) and `PairingPair`.
- `bn_x` (the BN seed, `4965661367192848881` — the SAME value
  `fp.zig`/`scalar.zig`'s defining-polynomial-family constant already
  cites) and `bn_ate_loop_param` (`= 6*bn_x+2`, comptime-derived, pinned
  byte/decimal-exact against the independently-published
  `py_ecc.bn128.bn128_pairing.ate_loop_count = 29793968203157093288` —
  see this file's own test).
- `multiMillerLoop`'s infinity-skip product wiring: a pair with either
  input at infinity contributes the trivial factor `1` and is SKIPPED —
  `millerLoop` is never invoked for it. An all-infinity `pairs` slice
  therefore returns `Fp12.one` WITHOUT touching either stub, gate
  irrelevant — the module's own `"multiMillerLoop never touches the
  stub on an all-infinity input"` test exercises exactly this, ungated.
- `pairing`/`pairingCheck`'s composition wiring (`finalExponentiation`
  composed with `multiMillerLoop`).
- `Fp12.cyclotomicSquare` — the ONE auxiliary primitive the final
  exponentiation's hard part needs beyond plain `Fp12` ring arithmetic —
  was ALREADY implemented and KAT-tested during the Part 3 field-tower
  pass (`fp12.zig`, Granger-Scott construction, generic in the tower's
  non-residues, so it required NO BN254-specific derivation beyond what
  Part 3 already did). Part 4 imports it as-is; **no new implementation
  decision was needed here** — this answers what would otherwise be an
  open scaffold question ("implement `cyclotomicSquare` now, or stub it
  for Fable too?"): it turned out already done.
- Every pinned KAT hex vector's OWN byte-parse/round-trip (independent of
  whether the pairing core exists yet to PRODUCE the values).

**Cores (Fable crypto-core pass, gate `pairing_core_implemented` now
`true`):**
- `millerLoop(p, q) Fp12` — the per-pair `6x+2` Miller walk (plain
  binary MSB→LSB over `6x+2`; NAF is a deferred optimization) with the
  BN-specific "Frobenius tail" (`Q1 = π(Q)`, `Q2 = π²(Q)`, then
  `f·line(T,Q1)`, `T+=Q1`, `f·line(T,−Q2)`). The KAT-caught subtlety
  the pass had to resolve: BN254's twist constant is `b' = 3/ξ`, so the
  untwisting map MULTIPLIES (`ψ(x',y') = (x'·w², y'·w³)`) and the sparse
  line lands in tower slots `(1, w, w³)` — NOT `bls12_381`'s
  `(1, w², w³)` shape (its twist is `b'=b·ξ`, whose untwist divides).
  Transcribing the BLS slot layout verbatim passes the self-inverse
  `pairingCheck` identities yet fails every byte-exact KAT — the
  "plausible-but-wrong" mode the byte-exact oracle exists to catch.
- `finalExponentiation(f) Gt` — the easy part (curve-generic,
  transcribed from `bls12_381.pairing.finalExpEasyPart`: `conj(f)·f⁻¹`
  then `·frob²`) composed with the BN-specific exact-`d` hard part
  (Scott-Benger-Charlemagne-Perez-Kachisa ePrint 2008/490 §7 vectorial
  addition chain, Devegili-Scott-Dahab 2007 §4 lineage — three `m^x`
  seed exponentiations via `cyclotomicSquare` + Frobenius/conjugate/mul
  combines; DIFFERENT from `bls12_381`'s Hayashida-Hayasaka-Teruya
  chain). NOT the Fuentes-Castañeda variant, which computes a fixed
  nontrivial POWER of `f^d` (bilinearity-equivalent, byte-different) and
  would fail the KAT. The chain's exponent was re-verified with
  independent big-integer arithmetic to equal `(p⁴−p²+1)/r` exactly
  before being trusted; the byte-exact py_ecc KAT then confirmed it
  end-to-end.

Both cores' doc comments in `pairing.zig` carry the full construction,
the sign/Frobenius-power-ordering footgun, and the numeric
re-verification — byte-exact-checked against the pinned KAT vectors.

## Part 4 — KAT generation

No numeric worked example for BN254's pairing exists in EIP-196/197's
spec text itself, so Part 4's KAT vectors were generated with
`ethereum/py_ecc`'s `bn128` module (`pip install py_ecc`, version current
as of 2026-07 — a mature, independently-authored reference
implementation; this is the task's own suggested KAT source) — used
strictly as a NUMERIC ORACLE for `pairing.zig`'s pinned test vectors, not
read/ported for algorithm shape (this module's OWN `millerLoop`/
`finalExponentiation` doc comments cite Devegili-Scott-Dahab/
Fuentes-Castañeda et al. directly, not `py_ecc`'s source — see `NOTICE`).

**The representation mismatch, and how it was bridged.** `py_ecc.bn128`
represents `Fp12` as a FLAT single-generator basis, `Fp[w]/(w^12-18w^6
+82)` (its own `bn128_curve.py` comment: "Field isomorphism from
Z[p]/x^2 to Z[p]/(x^2-18x+82)" — embedding its `Fp2`'s `i` as `w^6-9`).
This module's tower (`Fp12 = Fp6[w]/(w^2-v)`, `Fp6 = Fp2[v]/(v^3-ξ)`,
`ξ = 9+u`) gives `w^6 = v^3 = ξ = 9+u` — THE SAME defining relation
(`9+i = 9+(w^6-9) = w^6` in `py_ecc`'s basis), confirmed identically:
both towers' `w` satisfies `w^6 = 9+(the base Fp2 generator)`. Because
of this shared relation, a tower coefficient `a_{i,j,k}` (`i` = the
`Fp12`-level `w^i` index `0..1`, `j` = the `Fp6`-level `v^j` index
`0..2`, `k` = the `Fp2`-level `u^k` index `0..1`) maps DIRECTLY into
`py_ecc`'s flat 12-coefficient basis (index `f = 2j+i`, `0..11`) via:

```python
flat[f]   += a[i][j][0] - 9 * a[i][j][1]   # f = 2j+i, 0 <= f <= 5
flat[f+6] += a[i][j][1]
```

(the inverse — recovering tower coefficients from a `py_ecc` `FQ12`
value — is the direct algebraic inverse: `a[i][j][1] = flat[f+6]`,
`a[i][j][0] = flat[f] + 9*flat[f+6]`). This is an EXACT, LOSSLESS
Fp-linear bijection between the two 12-dimensional representations (both
towers are 12-dimensional `Fp`-vector spaces built as extensions of the
same base field `Fp`), not an approximation or a "close enough" numeric
match.

**Validated as a ring homomorphism before use** (the same discipline
`bls12_381/src/pairing.zig`'s own KAT comment documents: "the conversion
first validated as a ring isomorphism on random products") — NOT merely
asserted:
- On 20 random pairs of tower elements `A`, `B`: computed `A*B` with a
  from-scratch Python re-implementation of THIS module's own tower
  arithmetic (the same `fp2_mul`/`fp6_mul`/`fp12_mul` functions already
  established by this file's "Verification performed" §4 KAT
  generator), mapped both the product and the two factors into
  `py_ecc`'s flat basis, and confirmed `map(A)*map(B) == map(A*B)` under
  `py_ecc`'s own `FQ12.__mul__` — i.e. the map is a genuine ring
  homomorphism, not merely coefficient-position-compatible on the
  identity/generators alone.
- Confirmed `map(w_tower) == py_ecc`'s own `w = FQ12([0,1,0,...])`
  (both towers' generators coincide under the map, not just isomorphic
  up to scaling), and `map(w_tower)^6 == map(ξ_tower)` (the defining
  relation itself holds through the map).

**Vectors generated** (`p` = the BN254 base field modulus, `r` = the
group order; both `G1`/`G2` generators used are `py_ecc.bn128.G1`/`G2`,
confirmed byte-identical to this module's own `g1.zig`/`g2.zig`
generators before computing anything):
- `e_g1_g2_hex` = `map(py_ecc.bn128.pairing(G2, G1))` — `py_ecc`'s
  `pairing(Q, P)` argument order (Q first); its `miller_loop` already
  applies the full `f^((p^12-1)/r)` final exponentiation internally, so
  this is directly the fully-exponentiated `e(G1, G2)`, no extra step.
- `e_2g1_g2_hex` = `map(pairing(G2, [2]G1))`, cross-checked EQUAL to
  `map(pairing([2]G2, G1))` (both computed and compared inside Python
  before pinning — `e([2]P,Q) == e(P,[2]Q)`, a bilinearity sanity check
  on the ORACLE itself, independent of this module) and equal to
  `e_g1_g2^2` (also checked in Python).
- `e_3g1_g2_hex` = `map(pairing(G2, [3]G1))`, checked equal to
  `e_g1_g2^3` in Python.
- Sanity checks performed in Python before pinning (not merely assumed):
  `py_ecc`'s BN `ate_loop_count = 29793968203157093288` equals
  `6*4965661367192848881+2` exactly (this module's own
  `bn_ate_loop_param` derivation); `e(G1,G2) != 1`; `e(G1,G2)^r == 1`.

No sign-convention correction was needed (unlike `bls12_381`'s
py_ecc-cross-check, which needed a documented conjugation for the
negative BLS seed — `bls12_381/src/pairing.zig`'s own KAT comment):
BN254's seed `x` is POSITIVE and `py_ecc`'s `ate_loop_count = 6x+2` is
the same positive loop parameter this module's `bn_ate_loop_param`
already derives, so `py_ecc`'s pairing convention lines up with this
module's directly.

The Python script (generator + validator, not shipped/imported by the
module — same "kept for reproducibility" policy as this file's §4 field
-tower KAT generator) lives in scratch history only; reproducing it
requires `pip install py_ecc` plus the tower-arithmetic functions
already listed in this file's §4.

## Part 5 — EVM precompiles (`precompiles.zig`)

`precompiles.zig` implements the three EIP-196/197 EVM precompiles —
`ecAdd` (`0x06`), `ecMul` (`0x07`), `ecPairing` (`0x08`) — as PURE
composition over Parts 1-4: decode calldata with `g1.zig`/`g2.zig`'s
existing codecs, call an existing `G1`/`G2` group operation or
`pairing.pairingCheck`, re-encode the result. No new field/curve/pairing
arithmetic exists in this file.

**Tier: Sonnet, not Fable — see "Tier assessment" above for the Parts
1-4 precedent this continues.** The one property that could plausibly
look like a "judgment call" — MUST `ecPairing` reject an on-curve-but-
outside-subgroup `G2` operand — is not actually a judgment call: it is
EIP-197's own specified precondition (an unchecked small-subgroup point
makes the pairing forgeable, the standard pairing-cryptography pitfall
`g2.zig`'s own module doc comment already documents), and the check
itself (`g2.Jacobian.subgroupCheck`) already existed, already tested,
from Part 3. This file's only obligation was to remember to CALL it on
every decoded `G2` operand and to prove, with a test, that it actually
fires in the precompile path (see "Verification performed" below) — not
to derive why the check is needed or how to build it.

**Calldata padding.** EIP-196's own spec text ("Note about the change in
the way points and outputs are represented") and go-ethereum's
`core/vm/contracts.go` `getData(input, start, size)` helper (the de
facto interoperable behavior every mainnet client matches, confirmed
directly by several of the official `bn256Add.json` vectors below, e.g.
`cdetrio3`/`cdetrio5`) together specify: calldata shorter than a
precompile's fixed input width is RIGHT-PADDED with zero bytes; calldata
longer is TRUNCATED (only the needed prefix is read, any trailing bytes
ignored). `padTo` (`precompiles.zig`) reproduces this with a single
zero-fill-then-copy over the WHOLE fixed-width buffer rather than one
`getData` call per field; proven equivalent to independent per-field
`getData` calls for every length regime (empty / shorter-than-one-field
/ between-fields / exactly-enough / longer-than-needed) in that
function's own doc comment. `ecPairing` has NO such tolerance: its
calldata length MUST be an exact multiple of 192 (one `(G1,G2)` pair),
else the call fails outright (`error.BadLength`) — a different,
stricter rule EIP-197 states explicitly, not an oversight in `ecAdd`/
`ecMul`'s padding tolerance.

**`ecMul`'s scalar is not a validated `Fr`.** EIP-196's scalar operand
is used as a raw 256-bit big-endian integer, not rejected if `>= r`
(unlike `Fr.fromBytes`, which does reject non-canonical values — that
function exists for contexts needing a canonical scalar-field element,
e.g. a future Groth16 witness, which this operand is not). `ecMul`
therefore calls `g1.Jacobian.scalarMulBytes` (the arbitrary-width
big-endian-scalar engine `g1.zig`/`g2.zig` already use internally for
their own `[r]P == O` subgroup-check KATs) directly on the raw 32-byte
operand — computing `[scalar]P` for the LITERAL integer value. Because
`G1`'s cofactor is 1 (`P`'s order is exactly `r`), this is automatically
equal to `[scalar mod r]P` — no separate reduction step exists or is
needed, and none was added.

**Failure semantics.** Every error `PrecompileError`
(`g1.G1Error || g2.G2Error || error{BadLength, NotInSubgroup}`)
corresponds to a real EVM's revert-and-burn-all-gas condition on a
malformed/invalid precompile call. This module carries no gas/EVM model
of its own — mapping `error.*` to "revert" is a future EVM-interpreter
caller's job.

## Part 5 — KAT sourcing

Unlike Part 4 (no numeric worked example exists in EIP-196/197's spec
text itself, forcing a `py_ecc`-computed oracle), Part 5's KAT vectors
did not need to be generated at all: `ethereum/go-ethereum`'s own
`core/vm/testdata/precompiles/bn256Add.json` / `bn256ScalarMul.json` /
`bn256Pairing.json` (fetched directly from `raw.githubusercontent.com`,
2026-07-15 — NOT hand-transcribed) are the authoritative, widely-shared
precompile conformance vectors most mainnet clients (go-ethereum,
besu, erigon, reth, nethermind) test against — a STRONGER provenance
than Part 4's `py_ecc` oracle, since these are the actual EVM
ecosystem's shared ground truth, not merely one independent
implementation's output. All 49 vectors across the three files
(16 `ecAdd`, 19 `ecMul`, 14 `ecPairing`) are embedded verbatim in
`precompiles.zig`'s tests and checked byte-exact — see `NOTICE`'s item 5
for the provenance/licensing accounting.

**Coverage the vector set provides "for free"**, without any
self-constructed input needed:
- `ecAdd`'s short-input zero-padding (`cdetrio2`/`cdetrio3`/`cdetrio4`
  [empty input] /`cdetrio8`) and long-input truncation
  (`cdetrio5`/`cdetrio7`/`cdetrio10`/`cdetrio12`/`cdetrio14`) regimes,
  with REAL calldata exercising `padTo`'s equivalence argument above,
  not just the trivial `padTo`-of-empty-input case.
- `ecMul`'s scalar handling across small (`9`, `1`), maximal
  (`0xffff...ff`, wider than `r`), and exactly-`r`-ish (`cdetrio2`,
  scalar `= r-1`) magnitudes, plus `zeroScalar` (`[0]P = O`).
- `ecPairing`'s BOTH branches from OFFICIAL vectors, satisfying the task
  brief's "true AND false" requirement without any self-constructed
  pairing input: `jeff1`-`jeff5`, `empty_data` (`k=0`), `two_point_match
  _2/3/4`, `ten_point_match_1/2/3` are official TRUE vectors;
  `jeff6` and `one_point` (`e(G1,G2) != 1`, a single non-trivial pair)
  are official FALSE vectors. `empty_data` independently confirms the
  `k=0 -> true` empty-product rule this file's `ecPairingCheck` doc
  comment states.

**What the official vector set does NOT cover, and how this module
covers it instead** (both self-constructed, both clearly labeled as
such — self-consistency checks against this module's OWN prior test
constructions, not independent oracles):
- **The mandatory `G2` subgroup-check firing inside the precompile
  path.** No go-ethereum vector exercises an on-curve-but-outside-
  subgroup `G2` operand (real-world calldata from a functioning client
  never produces one; the official test suite is a conformance suite,
  not an adversarial-input fuzz corpus). `precompiles.zig`'s own test
  ("ecPairingCheck: on-twist-but-not-in-subgroup G2 operand is
  rejected") reuses the EXACT non-subgroup point `g2.zig`'s Part 3 test
  already constructed and independently verified in Python (`x = u`,
  `c0=0,c1=1`; that point's `y` and its "on-curve but `[r]P != O`"
  status were confirmed outside this module during Part 3 — see this
  file's Part 3 "Verification performed" entries), packages it as the
  `G2` half of a `192`-byte `ecPairing` calldata pair, and confirms
  `ecPairingCheck` returns `error.NotInSubgroup` rather than silently
  calling `pairing.pairingCheck` on an invalid input. This is the
  security-critical assertion Part 5's whole tier-assessment argument
  rests on (see above) — it is exercised, not merely asserted in a
  comment.
- **`ecPairing`'s `error.BadLength` precondition** (length not a
  multiple of 192) — no official vector is malformed this way (all 14
  `bn256Pairing.json` inputs are exact multiples of 192: `0, 192, 384,
  576, 1920`), so `precompiles.zig` adds a direct self-constructed test
  (lengths `100` and `191`) confirming the rejection.
- **`ecAdd`/`ecPairing` coordinate `>= p` and off-curve-point rejection**
  — covered by adapting `g1.zig`'s own already-independently-verified
  "off-curve `(1,3)`" and "coordinate `== p`" test inputs into
  `precompiles.zig`'s calling convention (calldata bytes, not a direct
  `Fp`/`Affine` construction) — a self-consistency check against Part
  1/3's own prior verification, not a new independent claim.

## Part 6 — Groth16 verifier (`groth16.zig`)

`groth16.zig` implements a Groth16 zk-SNARK proof VERIFIER over BN254 —
`VerifyingKey`/`Proof` structs and `verify`, the final part of this
module's arc. PURE COMPOSITION over Parts 1-4, same tier posture as
Part 5: the multi-scalar accumulation of the public-input commitment
(`msm`, a plain loop of `G1.Jacobian.scalarMul`/`add` — no batching/
Pippenger, deliberately, see "Backlog") and one `pairing.pairingCheck`
call over four `(G1,G2)` pairs. No new field/curve/pairing primitive.

**Tier: Sonnet, not Fable.** Same argument as Part 5's tier assessment:
the one property that could look like a judgment call — MUST `verify`
subgroup-check the proof's `B` operand — is EIP-197's/the standard
Groth16 verifier's own specified precondition (an unchecked
small-subgroup `B` makes the pairing forgeable), and the check itself
(`G2.Jacobian.subgroupCheck`) already existed, already tested, from
Part 3. This file's only obligations were: (1) remember to CALL it
(and `G1.isOnCurve` on `A`/`C`) on every proof field before trusting it,
(2) get the single-`pairingCheck`-product sign convention right (`-A`,
not `-C`/`-vk_x` — three algebraically-equivalent-looking choices, only
one of which matches the standard snarkjs/Ethereum-verifier convention),
and (3) wire the `IC[0] + Σ pub[i]·IC[i]` accumulation correctly. All
three were CONFIRMED against a byte-exact, independently-computed KAT
(below), not merely asserted — see `groth16.zig`'s own "KAT provenance"
doc comment for the `py_ecc` cross-check that pinned the sign
convention specifically.

**The verification equation** — `e(A,B) == e(α,β)·e(vk_x,γ)·e(C,δ)`,
checked as the single product `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) == 1` via
`pairing.pairingCheck` (Part 4) — and the `G1` multi-scalar accumulation
`vk_x = IC[0] + Σ_{i=1..n} pub[i]·IC[i]` are both spelled out in full in
`groth16.zig`'s own module doc comment; not duplicated here.

**Public inputs are `Fr`, not raw bytes.** `verify(vk, proof,
public_inputs: []const Fr)` — "reject a public input `>= r`" is enforced
by the TYPE (`Fr.fromBytes` already rejects non-canonical values,
`scalar.zig`), not a separate check inside this file. Same "make illegal
states unrepresentable" discipline the rest of this module's API already
uses.

**Malformed-proof vs. cryptographically-false-proof.** `verify` returns
`Groth16Error!bool`: `error.WrongPublicInputCount` is the one distinct
error (a call-SHAPE mismatch between `vk.ic.len` and
`public_inputs.len`, not a property of the proof); a proof point failing
`isOnCurve`/`subgroupCheck`, or a well-formed proof that simply doesn't
satisfy the pairing equation, both return ordinary `false` — from a
caller's perspective both are "this proof does not verify", and the task
brief's own acceptance criteria phrase both outcomes as "verifies
FALSE"/"rejected" rather than distinguishing them.

### Part 6 — KAT provenance

The positive vector (a proof that verifies TRUE) is a REAL,
independently-sourced snarkjs-produced Groth16/BN254 proof, NOT
self-generated by this module or its author (a self-made proof would
only prove self-consistency, not correctness against an independent
implementation — the task's own explicit non-goal for the positive
vector). Source: the Dark Forest v0.3 game's "move" circuit (a
proof-of-visibility zk-SNARK; Dark Forest is a well-known, widely-cited
production zkSNARK dApp from the Ethereum zk community),
`github.com/darkforest-eth/darkforest-v0.3`, path `circuits/move/`,
commit `1c83685e22e0463d5481c83e21616745b3204c9c` (fetched 2026-07-15):
`verification_key.json` (`nPublic: 5`, 6 `IC` points), `proof.json`
(`pi_a`/`pi_b`/`pi_c`), `public.json` (5 public-input integers).

**Field-name vintage, not a different protocol.** The JSON's field names
(`vk_alfa_1`/`vk_beta_2`/`vk_gamma_2`/`vk_delta_2`/`IC`,
`"protocol": "groth"`) are an EARLY snarkjs naming convention (before the
protocol string was renamed to `"groth16"`) for the SAME construction
this file implements — confirmed structurally (the `vk_alfabeta_12`
-shaped verifying key and the `IC`-indexed public-input commitment
exactly match `groth16.zig`'s own "verification equation" doc comment)
AND numerically (below), not merely assumed from the naming.

**Independently re-verified with `py_ecc` before being trusted as this
file's KAT** — a THIRD implementation, sharing no code with either
this module's own Zig field/pairing tower or snarkjs/circom's prover, so
it cannot share a bug with either side:
- A standalone Python script (venv-installed `py_ecc`, 2026-07-15)
  parsed the three JSON files, confirmed `vk_alfa_1`/`vk_beta_2`/
  `vk_gamma_2`/`vk_delta_2`/every `IC` entry AND the proof's `A`/`B`/`C`
  are each on their respective curve (`py_ecc.bn128.is_on_curve`).
- Computed `vk_x = IC[0] + Σ pub[i]·IC[i]` with `py_ecc`'s own EC
  arithmetic (`multiply`/`add`), confirmed on-curve.
- Confirmed `pairing(B, A) == pairing(beta, alpha) * pairing(gamma,
  vk_x) * pairing(delta, C)` (the two-sided form) AND the single-product
  form `pairing(B, -A) * pairing(beta, alpha) * pairing(gamma, vk_x) *
  pairing(delta, C) == FQ12.one()` — i.e. the EXACT sign convention
  (negate `A`, not `C`/`vk_x`) `groth16.zig`'s `verify` implements,
  confirmed to be the one that makes THIS specific real proof verify
  TRUE (py_ecc's `pairing(Q, P)` computes `e(P, Q)`, so this is
  literally `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) == 1` in this module's own
  `e(P,Q)` convention).
- Confirmed every tamper case `groth16.zig`'s tests exercise fails the
  equation in Python FIRST: `A.x+1`/`C.y+1`/`B.x.c0+1` each land
  OFF-curve (`py_ecc.is_on_curve` false, `py_ecc`'s own pairing raises on
  such input — mirroring this file's `isOnCurve`/`subgroupCheck`
  rejection path); negating `A` or `C` (an ON-curve, well-formed but
  WRONG point) makes the pairing PRODUCT `!= FQ12.one()`; `pub[0]+1`
  (still `< r`, a valid `Fr` value) changes `vk_x` and likewise breaks
  the product.

**Coordinate ordering — the snarkjs footgun, confirmed not merely
assumed.** `verification_key.json`/`proof.json`'s `Fp2` values
(`vk_beta_2`, `vk_gamma_2`, `vk_delta_2`, `pi_b`) are nested `[c0, c1]`
arrays in MATH order (real part first). `groth16.zig`'s `fp2FromDecimal`
reads the JSON's index-0 element as `c0` and index-1 as `c1` DIRECTLY —
the OPPOSITE of `g2.zig`'s EIP-197 byte-codec order (`c1||c0`,
imaginary-first). The Python cross-check above used the identical
`(c0, c1)` = `(arr[0], arr[1])` reading (`FQ2([c0, c1])`, `py_ecc`'s own
convention) and got a proof that verifies TRUE; swapping the reading to
`(c1, c0)` was tried during KAT development and confirmed the footgun is
real (not hypothetical): every swapped-order `Fp2` value (`beta`,
`gamma`, `delta`, `B`) landed OFF the twist entirely
(`py_ecc.is_on_curve` false for all four) rather than merely producing a
wrong-but-plausible point — a wrong `c0`/`c1` reading fails loudly here,
which is exactly why this module's OWN `isOnCurve`/`subgroupCheck`
guards inside `verify` are load-bearing, not redundant. See
`groth16.zig`'s module doc comment for the full ordering discussion.

**Provenance/licensing**: `darkforest-eth/darkforest-v0.3` carries no
explicit OSS license file (GitHub reports the repository license as
`NOASSERTION`). The three embedded JSON files are NUMERIC PROOF/KEY DATA
— elliptic-curve point coordinates and field elements, the deterministic
output of running the Groth16 protocol over a specific circuit/witness —
the same "public numeric conformance data, not copyrightable expression"
category this file's own "Part 5 — KAT sourcing" section and `NOTICE`
item 5 already treat `ethereum/go-ethereum`'s (LGPL-3.0) precompile test
vectors as; listed in `NOTICE` out of the same caution, not because this
data is source code or creative expression. No darkforest-v0.3 SOURCE
(circuit or application code) was read or ported — only the three
already-computed JSON data files were fetched.

## Verification performed

Every embedded constant was independently re-derived/cross-checked
with Python (`python3`, standard library only — no third-party crypto
package), OUTSIDE this module, before being pinned as a test vector or
comptime literal. Reproducible steps:

**1. Primality + BN polynomial-family re-derivation** (confirms `p_bytes`/`r_bytes`):

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
x = 4965661367192848881  # the BN seed
assert p == 36*x**4 + 36*x**3 + 24*x**2 + 6*x + 1
assert r == 36*x**4 + 36*x**3 + 18*x**2 + 6*x + 1
# both independently confirmed prime by a 40-round Miller-Rabin test
```

**2. `p`'s congruences** (confirms the algorithm-shape preconditions):
`p % 4 == 3`, `(p-1) % 3 == 0`, `(p-1) % 6 == 0` — all directly
computed.

**3. `G1`/`G2`-on-curve cross-check** (confirms `p` AND the `Fp6`
non-residue `ξ = 9+u` together, without this module implementing any
group arithmetic itself — see `fp.zig`'s own KAT test for the `G1`
half):

```python
# G1 = (1, 2) on y^2 = x^3 + 3 (EIP-196 / py_ecc bn128_curve.py)
assert (2*2) % p == (1**3 + 3) % p

# G2 on the sextic twist y^2 = x^3 + b2, b2 = 3/(9+u), using
# Fp2 = Fp[u]/(u^2+1), element (c0,c1) = c0 + c1*u:
def fp2_mul(a,b):
    a0,a1=a; b0,b1=b
    return ((a0*b0 - a1*b1) % p, (a0*b1 + a1*b0) % p)
def fp2_inv(a):
    a0,a1 = a
    n = pow((a0*a0 + a1*a1) % p, p-2, p)
    return ((a0*n) % p, ((-a1)*n) % p)
xi = (9, 1)
b2 = fp2_mul((3,0), fp2_inv(xi))
G2x = (10857046999023057135944570762232829481370756359578518086990519993285655852781,
       11559732032986387107991004021392285783925812861821192530917403151452391805634)
G2y = (8495653923123431417604973247489272438418190587263600148770280649306958101930,
       4082367875863433681332203403145435568316851327593401208105741076214120093531)
def fp2_add(a,b): return ((a[0]+b[0])%p,(a[1]+b[1])%p)
x3 = fp2_mul(fp2_mul(G2x,G2x), G2x)
assert fp2_mul(G2y,G2y) == fp2_add(x3, b2)  # True
```

(`G2x`/`G2y` are `py_ecc.bn128.bn128_curve.G2`'s published coordinates,
`FQ2([c0, c1])` meaning `c0 + c1*i`.)

**4. Full independent field-tower KAT generator.** A from-scratch
Python re-implementation of `Fp2`/`Fp6`/`Fp12` arithmetic (Montgomery
storage NOT used — plain `pow`/`%` big-integer arithmetic, deliberately
a DIFFERENT implementation strategy than this module's
`std.crypto.ff`-backed Zig code, so the two cannot share a bug) was
used to generate every KAT hex string pinned in `fp2.zig`/`fp6.zig`/
`fp12.zig`'s `test "KAT: ..."` blocks: `Fp2` multiplication and
inversion, `Fp6`/`Fp12` Frobenius coefficients (`γ_1`, `γ`), `Fp6`
multiplication and inversion, `Fp12` multiplication, and `Fr`'s 64-byte
`reduceWide` reduction. The generator (kept for reproducibility, not
shipped/imported by the module):

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
def fp_inv(a): return pow(a, p-2, p)

def fp2_add(a,b): return ((a[0]+b[0])%p, (a[1]+b[1])%p)
def fp2_sub(a,b): return ((a[0]-b[0])%p, (a[1]-b[1])%p)
def fp2_mul(a,b):
    a0,a1=a; b0,b1=b
    return ((a0*b0 - a1*b1)%p, (a0*b1+a1*b0)%p)
def fp2_sq(a): return fp2_mul(a,a)
def fp2_inv(a):
    a0,a1=a
    ninv = fp_inv((a0*a0+a1*a1)%p)
    return ((a0*ninv)%p, ((-a1)*ninv)%p)
FP2_ONE=(1,0); FP2_ZERO=(0,0)
XI = (9,1)  # Fp6 non-residue = 9+u

def fp6_mulByNonresidue(a):
    c0,c1,c2 = a
    return (fp2_mul(c2, XI), c0, c1)
def fp6_mul(a,b):
    a0,a1,a2=a; b0,b1,b2=b
    v0=fp2_mul(a0,b0); v1=fp2_mul(a1,b1); v2=fp2_mul(a2,b2)
    t0 = fp2_sub(fp2_sub(fp2_mul(fp2_add(a1,a2),fp2_add(b1,b2)),v1),v2)
    c0 = fp2_add(fp2_mul(t0, XI), v0)
    c1 = fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a0,a1),fp2_add(b0,b1)),v0),v1), fp2_mul(v2,XI))
    c2 = fp2_sub(fp2_add(fp2_sub(fp2_mul(fp2_add(a0,a2),fp2_add(b0,b2)),v0),v1),v2)
    return (c0,c1,c2)
FP6_ONE=(FP2_ONE,FP2_ZERO,FP2_ZERO)
def fp6_inv(a):
    a0,a1,a2=a
    c0 = fp2_sub(fp2_sq(a0), fp2_mul(fp2_mul(a1,a2),XI))
    c1 = fp2_sub(fp2_mul(fp2_sq(a2),XI), fp2_mul(a0,a1))
    c2 = fp2_sub(fp2_sq(a1), fp2_mul(a0,a2))
    t = fp2_add(fp2_mul(fp2_add(fp2_mul(a1,c2),fp2_mul(a2,c1)),XI), fp2_mul(a0,c0))
    tinv = fp2_inv(t)
    return (fp2_mul(c0,tinv), fp2_mul(c1,tinv), fp2_mul(c2,tinv))

def fp6_add(a,b): return tuple(fp2_add(x,y) for x,y in zip(a,b))
def fp6_sub(a,b): return tuple(fp2_sub(x,y) for x,y in zip(a,b))
def fp12_mul(a,b):
    a0,a1=a; b0,b1=b
    v0=fp6_mul(a0,b0); v1=fp6_mul(a1,b1)
    c0 = fp6_add(v0, fp6_mulByNonresidue(v1))
    c1 = fp6_sub(fp6_sub(fp6_mul(fp6_add(a0,a1),fp6_add(b0,b1)),v0),v1)
    return (c0,c1)

def fp2_pow(a, e):
    acc = FP2_ONE
    base = a
    while e > 0:
        if e & 1: acc = fp2_mul(acc, base)
        base = fp2_sq(base)
        e >>= 1
    return acc

gamma_1 = fp2_pow(XI, (p-1)//3)   # Fp6 Frobenius coefficient
gamma   = fp2_pow(XI, (p-1)//6)   # Fp12 Frobenius coefficient
```

(Every KAT test in this module cites which of these computations it
pins.) Hex encoding: each `Fp` value is
`format(x % p, '064x')` (32 bytes, big-endian); `Fp2`/`Fp6`/`Fp12`
concatenate their components HIGH-to-LOW (`c1||c0`, `c2||c1||c0`,
`c1||c0`) matching this module's own `toBytes` convention.

**5. `Fr.reduceWide` 64-byte KAT**: `int.from_bytes(b'\xff'*64, 'big')
% r`, computed directly in Python.

**6. Part 3 (`G1`/`G2`) — independent from-scratch Python EC
implementation.** Plain textbook AFFINE-coordinate short-Weierstrass
formulas over Python big integers (a DIFFERENT algorithm family than
this module's Jacobian/`std.crypto.ff` Zig code) were used to:

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
def fp_inv(a): return pow(a, p-2, p)
def fp2_mul(a,b):
    a0,a1=a; b0,b1=b
    return ((a0*b0 - a1*b1) % p, (a0*b1 + a1*b0) % p)
def fp2_sq(a): return fp2_mul(a,a)
def fp2_inv(a):
    a0,a1 = a
    n = fp_inv((a0*a0 + a1*a1) % p)
    return ((a0*n) % p, ((-a1)*n) % p)
def fp2_add(a,b): return ((a[0]+b[0])%p, (a[1]+b[1])%p)
def fp2_sub(a,b): return ((a[0]-b[0])%p, (a[1]-b[1])%p)

xi = (9, 1)
b2 = fp2_mul((3,0), fp2_inv(xi))  # G2's twist constant b'

G1 = (1, 2)
def g1_add(P, Q):  # standard affine EC addition/doubling over Fp
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q:
        if y1 == 0: return None
        m = (3*x1*x1) * fp_inv(2*y1) % p
    else:
        m = (y2-y1) * fp_inv((x2-x1) % p) % p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1-x3) - y1) % p
    return (x3, y3)
def g1_mul(P, k):
    R, Q = None, P
    while k > 0:
        if k & 1: R = g1_add(R, Q)
        Q = g1_add(Q, Q); k >>= 1
    return R

def g2_add(P, Q):  # same shape, over Fp2
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2 and fp2_add(y1,y2) == (0,0): return None
    if P == Q:
        if y1 == (0,0): return None
        m = fp2_mul(fp2_mul((3,0), fp2_sq(x1)), fp2_inv(fp2_mul((2,0), y1)))
    else:
        m = fp2_mul(fp2_sub(y2,y1), fp2_inv(fp2_sub(x2,x1)))
    x3 = fp2_sub(fp2_sub(fp2_sq(m), x1), x2)
    y3 = fp2_sub(fp2_mul(m, fp2_sub(x1,x3)), y1)
    return (x3, y3)
def g2_mul(P, k):
    R, Q = None, P
    while k > 0:
        if k & 1: R = g2_add(R, Q)
        Q = g2_add(Q, Q); k >>= 1
    return R
```

used to:
- confirm `p + 1 - t == r` (`t = 6x^2+1`) — the polynomial identity
  behind `G1`'s cofactor-1 claim;
- confirm `r * G1 == O` and `r * G2 == O` (via `g1_mul`/`g2_mul`) —
  independent of this module's own `[r]P == O` tests;
- generate the `[k]G1`/`[k]G2` byte-exact KAT vectors pinned in
  `g1.zig`/`g2.zig` for `k ∈ {2, 3, 5, 0x0123...cdef}`;
- search small `x = (0, c1)` values on the `G2` twist (via `fp2_sqrt`,
  the same complex-method construction as `fp2.zig`'s `Fp2.sqrt`) for
  one where `g2_mul(P, r) is not None` — `x = u` (`c1 = 1`) was the
  first hit, confirmed on-twist AND outside the subgroup, and is the
  vector `g2.zig`'s negative `subgroupCheck` test uses;
- confirm `twistB()`'s value (`b2` above) byte-for-byte against
  `g2.zig`'s comptime/runtime-computed result, and the EIP-197
  imaginary-first 128-byte encoding of the `G2` generator and `[2]G2`
  byte-for-byte against `g2.zig`'s `toBytes` output.

## NOTICE

Parts 1-3 needed no `NOTICE` entry: per `CONVENTIONS.md` §5's policy,
EIP-196/197 is a public specification (merger doctrine — not
copyrightable), and the field/curve constants themselves are
mathematical facts, not third-party expression; `py_ecc`'s published
constant VALUES were only cross-checked, never its source code ported
or studied for algorithm/API shape. **Part 4 changes this**: its KAT
harness uses `py_ecc.bn128`'s COMPUTED OUTPUT as a numeric oracle (not
merely its published constants), the same posture `bls12_381/NOTICE`
documents for its own `e(G1,G2)` cross-check — see
`modules/bn254/NOTICE` for the full entry (the basis-conversion
methodology, the ring-homomorphism validation, and what was/was not
read from `py_ecc`'s source).

## Backlog

- Part 3 (`G1`/`G2` group arithmetic — Jacobian/affine points,
  constant-time scalar multiplication, on-curve + subgroup checks):
  **done** (`g1.zig`/`g2.zig`).
- Part 4 (the optimal-ate pairing): **done** — `pairing.zig`'s
  `Gt`/`PairingPair`/loop-parameter constants/`multiMillerLoop`/
  `pairing`/`pairingCheck` wiring, the byte-exact KAT harness
  (`e_g1_g2_hex`/`e_2g1_g2_hex`/`e_3g1_g2_hex`, sourced from
  `ethereum/py_ecc`, see "Part 4 — KAT generation" above), AND both
  crypto cores — `millerLoop` (`6x+2` Miller loop with the BN-specific
  Frobenius-tail steps) and `finalExponentiation` (easy part + the
  BN-specific exact-`d` hard-part addition chain) — are implemented and
  tested, `gate.pairing_core_implemented` flipped to `true`; 123/123
  pass in Debug AND ReleaseFast, byte-exact against py_ecc. See "Part 4
  — pairing" above.
- Part 5: EIP-196/197 precompile-exact semantics (point-at-infinity
  encoding, gas-irrelevant validation rules, the exact error/success
  behavior the EVM expects) — depends on Part 4's core landing first
  (`pairingCheck` is the `ecPairing` precompile's actual primitive).
- Part 6 (Groth16 zk-SNARK verifier over the pairing): **done** —
  `groth16.zig`'s `VerifyingKey`/`Proof`/`verify`, byte/semantically
  exact against a REAL snarkjs-produced Groth16/BN254 proof
  (darkforest-v0.3's "move" circuit). See "Part 6 — Groth16 verifier"
  below.
- Persistent Montgomery storage / precomputed Frobenius-coefficient
  tables (performance-only; same deferred-optimization shape as
  `bls12_381`'s SPEC.md Backlog) — not needed until a later part's hot
  path (Miller loop) makes it worth the complexity.
- `G2`'s fast endomorphism-based subgroup check (untwist-Frobenius-twist
  — same technique `bls12_381/src/g2.zig`'s Backlog defers) — the
  simple `[r]P == O` form implemented here is correct and is what a
  scaffolding-stage Part 3 needs; a faster check is a follow-up
  optimization, not a correctness gap.
- `G2` cofactor value/`clearCofactor` — deliberately out of scope for
  this arc (see "Design & invariants" above); revisit only if a future
  part adds hash-to-`G2`.
