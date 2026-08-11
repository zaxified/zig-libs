# ed448 — SPEC

Ed448/X448, the "Goldilocks" 448-bit curve family; see [README.md](README.md)
for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: implemented.** Wire codecs, clamping, `dom4` domain-separation
framing, sign/verify/DH orchestration, AND the full field/scalar/curve
number-theory (`field.zig`'s `Fp448` arithmetic, `x448.zig`'s Montgomery
ladder, `ed448.zig`'s `Point` operations, `scalar.zig`'s mod-`L`
arithmetic) are real — see "Implementation notes (crypto core)" below
for how each formerly-stubbed piece was built.

## Design

- **Source of truth**: RFC 7748 (X448, §4.2/§5) and RFC 8032 (Ed448/
  Ed448ph, §5.2), both IETF standards-track specs with official test
  vectors (§5.2/§6.2 and §7.4/§7.5 respectively) — this module is
  clean-room from those two RFCs, no third-party source ported. Design
  references consulted for the field-representation CHOICE (not
  transcribed source): Mike Hamburg's original "Ed448-Goldilocks" paper
  and `libdecaf`'s 64-bit `p448` backend, both cited in `NOTICE`.
- **Two curve forms, one field.** `field.zig`'s `Fp448` (`p = 2^448 -
  2^224 - 1`) is the single base field both `x448.zig` (the Montgomery
  form, `curve448`, used for Diffie-Hellman) and `ed448.zig` (the
  twisted... actually UNTWISTED (`a=1`) Edwards form, `edwards448`, used
  for EdDSA signing) are built on — mirroring how
  `std.crypto.ecc.Curve25519`/`Edwards25519` share one field. The two
  curve forms are birationally equivalent (same underlying group, RFC
  7748 §4.1's map for the 25519 case; RFC 7748 does not spell out the
  448 map explicitly, but the relationship is the same shape) but this
  module does NOT implement a Montgomery<->Edwards point conversion —
  `x448.zig` and `ed448.zig` are independent consumers of `field.zig`,
  not of each other (matching `std.crypto.dh.X25519`/`sign.Ed25519`'s
  own independence, aside from the one-directional `fromEd25519`
  convenience `std.crypto.dh.X25519.KeyPair` offers that this module does
  NOT currently mirror — see "Out of scope" below).
- **Field representation: 8×56-bit limbs (hand-rolled), NOT
  `std.crypto.ff`.** `bls12_381/src/fp.zig` (this repository's other
  large-prime field module) delegates entirely to `std.crypto.ff.
  Modulus` — correct, but generic Montgomery arithmetic, not exploiting
  any structure in BLS12-381's prime. `p = 2^448 - 2^224 - 1` is
  DELIBERATELY chosen (RFC 7748 §4.2's own stated rationale) to admit a
  fast Solinas/Goldilocks-style reduction: both `2^448` and `2^224` land
  exactly on a limb boundary at 56 bits (`448 = 8×56`, `224 = 4×56`), so
  folding a double-width product back down is a handful of limb-aligned
  shifted adds, not a modulus-agnostic long division. Using `std.crypto.
  ff.Modulus(448)` here would be CORRECT but would throw away the one
  property that makes this specific prime interesting — see `field.zig`'s
  own module doc comment for the full reasoning (including the "8 spare
  headroom bits per `u64` limb for lazy-reduction carry accumulation"
  point, the same trick `std.crypto.ecc.Edwards25519`'s own 51-bit limbs
  use one field down).
- **`ed448.zig`'s `Point`: 3-coordinate projective, no `T`.** Unlike
  `std.crypto.ecc.Edwards25519` (`x`/`y`/`z`/`t`, the "extended
  coordinates" trick needed for TWISTED `a=-1` curves), edwards448 is
  UNTWISTED (`a=1`) and `d` is a quadratic non-residue mod `p` — RFC 8032
  §5.2.4 gives complete addition/doubling formulas directly in plain
  `(X,Y,Z)` projective coordinates, no fourth coordinate needed.
- **Ed448 cofactor handling.** edwards448's cofactor is 4 (vs edwards25519's
  8) — `2^446 - ...` divides `#E(edwards448)` by exactly 4. `verify` uses
  the COFACTORED check RFC 8032 §5.2.7 explicitly permits (`[4][S]B =
  [4]R + [4][k]A'`), matching `std.crypto.sign.Ed25519`'s own default
  cofactored `verify()` for the analogous reason — see "Threat model"
  below for why cofactored (not cofactorless) is this module's only
  variant so far.
- **`dom4` — always non-empty, unlike Ed25519's `dom2`.** RFC 8032 §5.1:
  Ed25519's plain (non-`ctx`, non-`ph`) mode uses an EMPTY `dom2` — no
  domain separation at all, which is why `std.crypto.sign.Ed25519.sign`
  needs no context parameter. Ed448 has NO such "plain, no domain
  separation" mode: `dom4(phflag, ctx)` — `"SigEd448" || octet(phflag) ||
  octet(len(ctx)) || ctx` — is ALWAYS absorbed, even for an empty `ctx`
  (`len(ctx) = 0`, but the `"SigEd448"` tag and the two length/flag bytes
  are still hashed). This is why `ed448.sign`/`verify`'s signatures
  always take a `ctx: []const u8` parameter (empty slice is a valid,
  common choice, but it is never OMITTED from the hash the way Ed25519's
  plain mode omits `dom2` entirely).
- **`scalar.zig`'s 57-byte width vs `field.zig`'s 56-byte width.** RFC
  8032 uses one uniform `b=456`-bit / 57-byte container for BOTH scalars
  (mod `L`, actually 446 bits) and point coordinates (mod `p`, actually
  448 bits) — the extra byte beyond `p`'s native 56-byte width exists
  ONLY to make room for a point's sign bit (RFC 8032 §5.2.2). `field.zig`
  itself stays at the tighter, RFC-7748-native 56-byte width (matching
  X448's own u-coordinate encoding) since a bare field element carries no
  sign bit of its own; `ed448.zig`'s `Point.toBytes`/`fromBytes` do the
  56-byte-`Fe` <-> 57-byte-point-encoding conversion at the point layer,
  not inside `field.zig`.

## Threat model / limits

- **Constant-time posture (as implemented).** Every secret-input path is
  branch-free with fixed iteration counts: `field.zig`'s
  `add`/`sub`/`mul`/`square` (fixed carry/fold rounds, mask-select
  conditional subtracts), `pow` (square-and-always-multiply,
  mask-selected — constant-time in base and exponent both, though every
  current caller's exponent is public), `isZero`/`eql` (accumulator
  compares, no early exit), `ctSelect`/`ctSwap` (byte-mask merges);
  `x448.zig`'s ladder (fixed 448 iterations, `ctSwap` swaps);
  `ed448.zig`'s `Point.mul` / `mulBasePoint` (fixed 112 nibble windows,
  each a masked 16-entry table scan plus an unconditional point-add) —
  used by keygen and signing, and by `decaf448`;
  `scalar.zig`'s `reduceWide`/`add`/`mul`/`mulAdd` (fixed-iteration
  binary reduction, branch-free conditional subtracts). Deliberately
  VARIABLE-time, public inputs only: `verify`/`verifyPh` (`Point.
  fromBytes`'s decode control flow, `equivalent`'s early-`and`, the
  final accept/reject branch) and the byte-codec range checks on
  caller-supplied wire data. The one data-dependent `catch` on the
  secret path — the ladder's `z_2.invert() catch Fe.zero` — branches
  only on whether the PUBLIC input point has small order, never on
  scalar bits (see `ladder`'s comment). KATs cannot detect timing
  side-channels — so this posture is MEASURED, not merely constructed,
  and since 2026-08-11 the measurement is a **committed program** rather
  than a number to take on faith:
  [`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), run by
  `scripts/ctgrind.sh ed448`. It marks the seed `MAKE_MEM_UNDEFINED`,
  forces a volatile reload, and drives it through two targets. **Full
  control table** (zig 0.16.0, valgrind 3.26.0, x86_64, ReleaseFast,
  2026-08-11; `in-file` = memcheck CONTEXTS whose stack names an `ed448`
  source):

  | target | `-fvalgrind` | seed tainted | total contexts | in `ed448` src | exit |
  |---|---|---|---|---|---|
  | `full` (`KeyPair.create` + `sign` + `x448.scalarmult`) | yes | **yes** | 9 | **3** | 99 |
  | `full` | yes | no | 0 | 0 | 0 *(control)* |
  | `full` | **no** | yes | 0 | 0 | 0 *(trap)* |
  | `ladder` (`Point.mul` + `Point.mulBasePoint`, no `toBytes`) | yes | **yes** | 12 | **0** | 99 |
  | `ladder` | yes | no | 0 | 0 | 0 *(control)* |
  | `ladder` | **no** | yes | 0 | 0 | 0 *(trap)* |

  All three `full` contexts are the SAME line — `Fe.invert`'s
  `if (a.isZero())` guard at `field.zig:473` — reached from
  `Point.toBytes` (`ed448.zig:314`, once from `KeyPair.create` and once
  from `signInternal`) and from the X448 ladder's final `z_2.invert()`
  (`x448.zig:156`). Read them yourself with
  `scripts/ctgrind.sh --stacks ed448` rather than trusting this
  sentence. Neither is a leak, and neither may be removed: for
  `Point.toBytes` the operand is a projective `Z` on a complete Edwards
  curve, so the branch outcome is invariantly "nonzero" for every
  scalar; for the ladder it is the small-order case above, fixed by the
  public input point. Both are genuine VALIDATIONS
  (`error.NotInvertible` on zero), the opposite of the scalar-derived
  rejection `ecvrf` had to strip out of `std`'s `Edwards25519.mul` —
  which this module is not exposed to, since `Point.mul` has no
  rejection and no error union.

  The non-zero `total` on both rows is the propagation witness: the
  taint demonstrably reached the harness's (non-constant-time) hex
  formatter, so `ladder`'s **0** means "no branch found", not "the taint
  never arrived". `ladder` uses `Fe.toBytes` rather than
  `Point.toBytes` precisely so the `Fe.invert` context above cannot
  double as its own witness.

  **Teeth, measured 2026-08-11.** Re-introducing a variable-time
  `if (nibble != 0) acc = acc.add(table[nibble]);` in `Point.mul` moves
  the `ladder` row from **12 total / 0 in-file** to **10 / 4** (and
  `decaf448`'s own harness, which rides this ladder, from 6/0 to 4/4) —
  the harness reaches the code it claims to. It does NOT move the `full`
  row, which stays 3: `KeyPair.create`/`sign` use the fixed-base
  `mulBasePoint` comb and X448 has its own ladder, so `Point.mul` is not
  on that path at all. Reverted; `cmp` against a pre-mutation copy
  confirmed byte-identical. *(An earlier note recorded this mutation as
  "report 860" — that was the ERROR count, not the context count;
  measured here as 421 errors from 4 contexts. Errors and contexts are
  not interchangeable and the earlier phrasing mixed them.)*
- **X448's `scalarmult` REJECTS non-canonical `u`** rather than silently
  masking the high bit the way RFC 7748 §5's own text permits
  ("implementations SHOULD mask the most significant bit in the final
  byte"). This mirrors `std.crypto.dh.X25519.scalarmult`'s own behavior
  on the equivalent 25519 case (`Curve25519.fromBytes` rejects
  non-canonical input via `field.zig`'s `Fe.fromBytes`) — a peer sending
  an out-of-range `u`-coordinate that gets silently reinterpreted as a
  DIFFERENT value than the peer intended is a worse failure mode than a
  hard reject, even though the RFC treats masking as compliant.
  Consumers needing strict RFC-permissive masking behavior instead of
  this module's stricter reject must currently mask the byte themselves
  before calling `scalarmult` (no built-in switch exists for this).
- **X448/Ed448 both use SECRET material inside field/scalar arithmetic**
  (X448: the private scalar inside the ladder; Ed448: the signing scalar
  `s` inside `mulAdd`, the ephemeral nonce `r` inside `Point.mul`). Every
  stub touching those values documents the constant-time requirement in
  its own doc comment (see above); `Fe.invert`'s use inside `Point.
  toBytes` operates on a coordinate `Z`, not directly secret, but should
  still avoid branching on its value out of general hygiene.
- **Ed448's `verify` uses cofactored (not cofactorless) checking.** Same
  rationale `std.crypto.sign.Ed25519`'s own default `verify()` documents:
  broader interoperability, aligns with common batch-verification
  approaches. A hypothetical `verifyStrict` (cofactorless, RFC 8032
  §5.2.7's `[S]B = R + [k]A'` variant) is NOT currently implemented — see
  "Out of scope" below.
- **All-zero X448 shared secret**: RFC 7748 §6.2 notes an X448 output can
  be the all-zero value if a peer sends a small-order `u`-coordinate;
  callers SHOULD check for and reject the all-zero shared secret (the RFC's
  own recommendation) — this module does NOT perform that check
  automatically inside `scalarmult`/DH helpers; it is left to the
  protocol layer built on top, matching `std.crypto.dh.X25519`'s
  identical choice to leave the check to the caller.

## Out of scope (this scaffold)

- **decaf448** — the prime-order-group wrapper that eliminates
  edwards448's cofactor-4 subgroup entirely (a distinct, separate
  construction layered on top of, not a variant of, plain Ed448). Not
  requested by the task that produced this scaffold; a future module in
  its own right if ever needed.
- **Hash-to-curve / Elligator2 for edwards448** — RFC 9380 defines one
  (`edwards448_XMDSHA512_ELL2_RO_`/`_NU_`, mirroring `std.crypto.ecc.
  Edwards25519.fromString`'s RFC-9380 support for the 25519 case); not
  required for plain X448 DH or Ed448 signing, and not implemented here.
- **`X448.KeyPair.fromEd448`** — the X25519-side convenience
  `std.crypto.dh.X25519.KeyPair.fromEd25519` offers (deriving an X25519
  key pair from an Ed25519 one via the birational map) has no `ed448.zig`
  analogue in this scaffold; `x448.zig` and `ed448.zig` are independent
  consumers of `field.zig`, not cross-wired to each other.
- **Ed448 batch verification / key blinding** — `std.crypto.sign.
  Ed25519` offers `verifyBatch` and a `key_blinding` submodule; neither
  has an Ed448 analogue here.

## Implementation notes (crypto core, 2026-07-15)

The formerly-stubbed number theory, as built (each function's own doc
comment carries the details):

1. **`field.zig`'s `Fp448` arithmetic.** `mul` is an 8×8-limb schoolbook
   multiply into u128 column accumulators, carried into 16 clean 56-bit
   limbs, then Goldilocks-folded: writing the 896-bit product as four
   224-bit chunks `A + B*2^224 + C*2^448 + D*2^672` and using `2^448 ≡
   2^224 + 1`, `2^672 ≡ 2*2^224 + 1 (mod p)` gives `(A + C + D) +
   (B + C + 2D)*2^224` — all limb-aligned, no cross-limb shifting (the
   point of the 56-bit layout). The shared reduction tail
   (`reduceAfterFold`) takes 8 accumulators `< 2^58`, runs a FIXED three
   carry-propagate+fold rounds (a documented bounds argument shows round
   3 can never carry out), then one branch-free conditional subtract of
   `p` (`condSubP`: trial subtraction + mask select). `add` feeds limb
   sums straight into that tail; `sub` computes `a + 2p - b` per limb
   (never negative, no borrow chain) into the same tail; `neg` is
   `sub(0, a)`; `square` is `mul(a, a)` (dedicated squaring is a
   performance follow-up). `invert` = Fermat `a^(p-2)`; `sqrt` =
   `a^((p+1)/4)` + square-check (`p ≡ 3 (mod 4)`); both via `pow`, a
   square-and-ALWAYS-multiply that mask-selects the multiply result in
   or out — constant-time in the base AND (beyond requirements) in the
   exponent. `isZero`/`eql` are OR/XOR-accumulator comparisons with no
   early exit.
2. **`x448.zig`'s `ladder`** — RFC 7748 §5's recurrence, transcribed
   verbatim: fixed 448 iterations, `Fe.ctSwap` conditional swaps driven
   by the running swap bit, `a24` as a comptime-built `Fe`. The final
   `x_2 * z_2^(p-2)` recovery uses `invert() catch Fe.zero` — for a
   small-order input driving `z_2` to 0 the RFC formula yields 0, which
   the catch reproduces exactly (the caught branch depends only on the
   PUBLIC input point, never on scalar bits).
3. **`ed448.zig`'s `Point`** — `add`/`dbl` are RFC 8032 §5.2.4's
   complete-addition/dedicated-doubling formulas verbatim; `neg` flips
   `x`; `equivalent` is the cross-multiplied projective comparison (no
   inversion). `mul` is a constant-time left-to-right double-and-add
   with a FIXED 448 iterations (bits 447..0 — NOT only `L`'s 446 bits:
   the RFC 8032 §5.2.5 CLAMPED secret scalar has bit 447 set and is
   deliberately used un-reduced by keygen/signing), computing the point
   addition unconditionally each round and mask-selecting it in or out
   via the componentwise `ctSelect`.
4. **`scalar.zig`'s mod-`L` arithmetic** — internal 56-bit u64 limbs
   (9 per scalar). Since `L` has no Solinas structure, reduction is a
   generic constant-time binary long division (`reduceLimbs`): one fixed
   iteration per input bit, each doing `r = 2r + bit` then a branch-free
   conditional subtract of `L` (`condSubL`, same trial-subtract+select
   shape as the field's). `reduceWide` runs it over the 114-byte digest
   (17 limbs); `mul` runs a 9×9 schoolbook product (accepting un-reduced
   456-bit inputs — the clamped scalar again) through the same
   reduction; `add` is one limb add + one conditional subtract; `mulAdd`
   is the doc-sanctioned `add(mul(a, b), c)` composition.

One scaffold bug was found and fixed during this pass: `Point.fromBytes`
carried a "defensive clear" of byte 55's top bit before decoding `y` —
but bit 447 IS part of `y` (`p < 2^448`; only byte 56's low 7 bits are
required-zero padding), so the clear silently corrupted every point with
`y >= 2^447` (about half of all points — including any signature whose
`R` lands there). Removed; the required padding check on byte 56 stays.

Byte-exact oracle for all of the above: `kat_vectors.zig`'s official RFC
7748 §5.2/§6.2 (X448) and RFC 8032 §7.4/§7.5 (Ed448/Ed448ph) vectors,
exercised end-to-end by `kat_test.zig` — which needed NO changes for the
crypto core to turn it green, as designed. `field.zig`, `x448.zig`,
`ed448.zig`, and `scalar.zig` each additionally carry their own
self-check tests (field inverse/sqrt/mul-square agreement, point
encode/decode round-trips and invalid-encoding rejects, scalar
wrap-around identities) independent of the KAT vectors.

Deferred (unchanged from the scaffold's "Out of scope" list): decaf448,
hash-to-curve/Elligator2 (RFC 9380), `fromEd448` key conversion, batch
verification / key blinding, plus the performance follow-ups noted
inline (dedicated squaring, windowed scalar mul, `mulSmall`, fused
`mulAdd` reduction).

## Verification

- `zig build test-ed448` (Debug) and `zig build test-ed448
  -Doptimize=ReleaseFast`: **all tests pass in both modes, no panics**
  (verified 2026-07-15, the day the crypto core landed). `zig fmt
  --check modules/ed448/` is clean.
- Byte-exact KATs: X448 RFC 7748 §5.2 vectors 1+2, the
  §5.2 1-iteration vector, the §6.2 Alice/Bob DH example (public keys +
  shared secret both directions); Ed448 RFC 8032 §7.4 Blank / 1 octet /
  1 octet-with-context / 11 octets (keygen public key, 114-byte
  signature, verify-accept, tamper-reject each); Ed448ph §7.5 "TEST
  abc"; plus context-binding and Ed448-vs-Ed448ph cross-rejection
  property tests.
