# musig2 — SPEC

MuSig2 multi-signature scheme over secp256k1 (BIP327); see
[README.md](README.md) for purpose and API. Provenance: see
[NOTICE](NOTICE).

**Status: complete (v2, tweak-aware)** — the full BIP327 core signing flow
(`KeyAgg`/`NonceGen`/`NonceAgg`/`GetSessionValues`/`Sign`/
`PartialSigVerify`/`PartialSigAgg`) AND key tweaking (`ApplyTweak` —
`KeyAggContext.applyTweak`, plain and x-only, composing via
`gacc`/`tacc`) are implemented and byte-exact against the official BIP327
vectors (including every `tweak_vectors.json` case and `sig_agg`'s two
tweaked cases); the final aggregate signature verifies under plain
`bip340.verify` against the (possibly tweaked) aggregate key. See "Out of
scope" for what is still deliberately omitted (`DeterministicSign`) and
"Done record" for the implementation passes' crypto-core notes.

## Design

- **Source of truth**: BIP327 ("MuSig2 for BIP340-compatible
  Multi-Signatures", `bitcoin/bips`), consumed directly as
  `bip-0327.mediawiki`. The curve group is `std.crypto.ecc.Secp256k1`
  (same as `bip340`); the tagged-hash construction, x-only public-key
  convention, and the BIP340 challenge tag are all reused from the
  sibling `bip340` module rather than re-derived.
- **Five NEW domain tags** beyond BIP340's three, all fed through
  `bip340.taggedHash`/`bip340.hash.taggedHasher` (which are generic over
  any comptime tag string, not just BIP340's own): `"KeyAgg list"`,
  `"KeyAgg coefficient"`, `"MuSig/noncecoef"`, `"MuSig/aux"`,
  `"MuSig/nonce"` — see `list_tag`/`coefficient_tag`/`noncecoef_tag`/
  `aux_tag`/`nonce_tag` in `root.zig`. The final signature's challenge
  hash reuses BIP340's own `"BIP0340/challenge"` tag directly (`bip340
  .hash.challenge_tag`) — this is by design, not a coincidence: a MuSig2
  aggregate signature IS a plain BIP340 signature, verifiable by
  `bip340.verify` with no knowledge that multiple signers produced it.
- **Plain vs. x-only public keys**: unlike `bip340.XOnlyPublicKey`
  (32-byte, implicit even-y), every MuSig2 PARTICIPANT key is a 33-byte
  SEC1-compressed `PlainPublicKey` (`cpoint`/`cbytes`, BIP327
  §"Notation") — aggregation needs each signer's REAL point (possibly
  odd-y); only the final AGGREGATE key is reduced to x-only
  (`KeyAggContext.getXonlyPubkey`).
- **`cpoint`/`cpoint_ext`/`cbytes`/`cbytes_ext`** (`root.zig`, private):
  built entirely on `bip340.XOnlyPublicKey`'s already-audited parse/lift
  plus a parity-negate for the `prefix == 3` case; `cbytes` is literally
  `Secp256k1.toCompressedSec1` (reused, not reimplemented — CONVENTIONS
  .md §1). No new curve-point-parsing logic exists in this module.
- **Every wire type validates like `bip340`'s codecs do**:
  `PlainPublicKey`/`PubNonce`/`AggNonce` all validate EAGERLY at
  `fromBytes` (mirroring `bip340.XOnlyPublicKey`/`Signature`), and their
  accessor methods (`.point()`/`.points()`) re-validate so they stay safe
  on hand-constructed values. `SecNonce` is the one exception — the spec
  itself treats `secnonce`'s range-validity as a `Sign`-TIME failure
  ("Secnonce is invalid which may indicate nonce reuse"), not a
  parse-time one, so `SecNonce.fromBytes` is a raw copy and
  `k1Scalar`/`k2Scalar` do the range check.
- **`keyAgg`/`nonceAgg`/`sign`/`partialSigVerify`/`partialSigAgg` all
  validate their own list/argument-level inputs** before any aggregation
  arithmetic runs: each does a genuine per-item pass (every pubkey via
  `PlainPublicKey.point()`, every pubnonce via `PubNonce.points()`, every
  partial signature via a canonical-scalar re-check) and returns a real
  error the moment anything fails — matching BIP327's own algorithms,
  which specify these checks as part of the algorithm itself ("fail if
  that fails and blame signer i"), not as a caller-side precondition.
  This is why every official "invalid contribution" KAT vector is safe to
  exercise directly against the composite function, not just the leaf
  codec (see `kat_test.zig`'s per-test comments for exactly which vectors
  are — and are deliberately NOT — exercised this way, and why).
- **`NonceGen`** (`nonceGen` in `root.zig`) is structurally identical to
  `bip340.sign`'s nonce derivation (tagged hash → `int(...) mod n` →
  `k·G`), with no parity ambiguity and no rogue-key surface. Byte-exact
  against all 4 official `nonce_gen_vectors.json` cases, including the
  "every optional argument absent" case.
- **`keySort` is real** — pure lexicographic byte-sort
  (`std.mem.sort`/`std.mem.order`), byte-exact against
  `key_sort_vectors.json`.

## Threat model / limits

- **The "second key" coefficient-1 rule and rogue-key resistance**: MuSig2's
  core defense against a *rogue-key attack* (where a malicious co-signer
  picks their public key as a function of the honest signers' keys to
  cancel out their contribution to the aggregate, letting them forge
  alone) is `KeyAggCoeffInternal`'s hash-derived coefficient `a_i =
  int(taggedHash("KeyAgg coefficient", L ‖ pk_i)) mod n`, EXCEPT for
  whichever key equals `GetSecondKey`'s result, which gets the fixed
  coefficient `1` (a documented, provably-safe optimization — see the
  BIP327 rationale footnote on `KeyAggCoeffInternal` — NOT a shortcut that
  weakens the scheme). Getting the "which key is 'the second key'" rule
  subtly wrong (e.g. picking `pk_1` itself, or picking BY INDEX instead of
  BY VALUE when the list contains duplicates) reintroduces exactly the
  rogue-key weakness the hash coefficients exist to prevent. `getSecondKey`
  is a pure byte comparison; `keyAggCoeffInternal` compares `pk' == pk2`
  BY VALUE exactly as the spec writes it, and `keyAgg` fails on an
  infinite `Q` (the `key_agg` vectors with duplicated keys — cases 2/3 —
  pin the by-value rule byte-exactly).
- **Nonce aggregation and the point-at-infinity substitution**: BIP327's
  "Dealing with Infinity in Nonce Aggregation" section is the single most
  subtle correctness/security interaction in this scheme. An `AggNonce`'s
  halves legitimately CAN be the point at infinity (either a dishonest
  signer's malicious pubnonce, or negligible-probability honest
  cancellation) — but a final BIP340 nonce `R` can never be infinite (no
  valid Schnorr signature has `x(R)` undefined). The spec's fix: if the
  combined `R' = R1 + b·R2` is infinite, `GetSessionValues` substitutes the
  GENERATOR `G` for `R` and continues signing anyway (rather than aborting)
  — this lets the protocol still surface WHICH signer was dishonest (via
  the subsequent partial-signature verification failing), instead of
  deadlocking. Silently rejecting an infinite `R'` instead of substituting
  `G` is a correctness bug that only manifests under adversarial or
  extremely-unlucky honest conditions — exactly the kind of edge case a
  KAT vector (`nonce_agg_vectors.json`'s "Sum of second points... is point
  at infinity" case, and `sign_verify_vectors.json`'s "Both halves of
  aggregate nonce correspond to point at infinity" case) exists to catch,
  and exactly the kind a hand-rolled implementation is likely to get wrong
  by "obviously" rejecting infinity everywhere.
- **The parity/`g`/`gacc` sign-flip chain (the single easiest bug to
  introduce)**: BIP327's aggregate key, its nonce, and every signer's
  effective secret key are all silently negated (multiplied by a `±1 mod
  n` factor: `g`, `gacc`, or the nonce parity mask) at several points, to
  keep everything consistent with an X-ONLY final public key and an
  even-Y final nonce — required because BIP340 signatures only ever
  commit to even-Y points, but an aggregate of arbitrary points is
  even-Y only by chance. Three DISTINCT sign-flips interact:
    1. **KeyAgg's `gacc`/`tacc` tweak accumulators** (BIP327 "Negation Of
       The Secret Key When Signing") — `1`/`Scalar.zero` for an untweaked
       session; each `applyTweak` step updates them as `gacc' = g·gacc`,
       `tacc' = t + g·tacc` (where `g` is the x-only-tweak parity flip of
       THAT step's pre-tweak `Q`, from the shared `gFromQ` helper — a plain
       tweak always has `g = 1`). This composition is exactly what lets a
       whole tweak CHAIN collapse into single terms downstream: `sign`'s
       `d = g·gacc·d' mod n` un-flips the signer's secret through every
       accumulated negation at once, and `partialSigAgg`'s `s = Σs_i +
       e·g·tacc mod n` adds the entire accumulated tweak offset once.
       Getting the ORDER wrong (e.g. `tacc' = g·(t + tacc)`) or applying
       `g` to the wrong step's `Q` silently re-keys the signature — the
       official `tweak_vectors.json` chains (plain/x-only in all four
       orderings, up to 4 tweaks deep) pin every combination byte-exactly.
    2. **`g` = whether the (tweaked) aggregate key `Q` needed negating**
       to become the even-Y final public key — computed independently,
       and identically, by BOTH `sign` (to negate the signer's `d'`) and
       `partialSigVerifyInternal` (to negate the coefficient side, "
       Negation Of The Individual Public Key When Partially Verifying") —
       these two computations MUST agree, or a partial signature that a
       correct signer produced will fail a correct verifier's check.
    3. **The nonce parity mask** (`k1,k2 = k1',k2'` or `n-k1',n-k2'`
       depending on `has_even_y(R)`, `R` = the FINAL session nonce, not
       either signer's own raw nonce point) — `bip340.sign`'s own
       step-7 already establishes the pattern `sign` follows (a
       constant-time masked select, never a branch on the parity bit
       itself, since which nonce got negated is a secret-derived bit
       that a timing/branch side channel could turn into a
       nonce-reuse-shaped key leak).
  Getting ANY of these three sign-flips backwards does not crash or
  obviously misbehave — it silently produces signatures for a key related
  to, but different from, the intended aggregate (or partial signatures
  that verify against the wrong effective key), which is exactly why this
  class of bug is MuSig2's most common from-scratch-implementation
  mistake and why every core's doc comment spells out the flip direction
  explicitly rather than leaving it implicit in the surrounding algebra.
  Implementation notes: all three of `sign`/`partialSigVerifyInternal`/
  `partialSigAgg` obtain `g` from the ONE shared `gFromQ` helper (they
  cannot disagree); the nonce parity mask in `sign` is a constant-time
  masked byte-select copied from `bip340.sign`'s step 7; and the
  `verify_fail` vector "wrong signature = the negation of a valid one" is
  the KAT that would catch a flipped `g`/parity in any of the three.
- **Nonce reuse**: same failure mode as `bip340`'s own `SPEC.md` documents
  for its single-signer nonce — reusing a `SecNonce` (calling `sign` twice
  with the same one, even for different messages/co-signer sets) leaks
  the signer's secret key via the standard two-equations-two-unknowns
  Schnorr algebra. This module cannot enforce "used at most once" itself
  (see `SecNonce`'s doc comment) — that is a caller-side/consumer-side
  responsibility (e.g. zeroizing the `SecNonce` value immediately after
  the one `sign` call that consumes it).
- **The mandatory self-verify in `Sign`**: BIP327's `Sign` algorithm
  requires running `PartialSigVerifyInternal` on the freshly-produced
  partial signature before returning it — the same fail-closed philosophy
  `bip340.sign`'s step-10 self-check already establishes in this
  collection (never publish a signature that doesn't verify against its
  own inputs; a computation fault should surface as an error, never as a
  maybe-bad signature that could leak key material). `sign` performs this
  check unconditionally and returns `error.SignatureVerificationFailed`
  (never the unverified `s`) if it does not pass.

## Tweaking (implemented in v2)

Formerly out of scope; implemented exactly along the seam v1 left open
(the formulas in `sign`/`partialSigVerifyInternal`/`partialSigAgg` were
already written in their general `gacc`/`tacc` form — the tweak pass
changed NONE of them, it only made the accumulators take non-trivial
values):

- **`KeyAggContext.applyTweak(tweak, is_xonly)`** = BIP327 `ApplyTweak`
  (covering both `ApplyPlainTweak` and `ApplyXonlyTweak` via the flag):
  `g = 1` (plain) or `gFromQ(Q)` (x-only — the flip only when the
  CURRENT `Q` has odd y); `t = int(tweak)`, `error.TweakOutOfRange` if
  `t >= n`; `Q' = g·Q + t·G`, `error.TweakedKeyIsInfinite` if infinite;
  `gacc' = g·gacc`, `tacc' = t + g·tacc` (all mod n). Multiple tweaks
  compose by repeated application — see the threat model's item 1 for why
  the accumulator order matters and which vectors pin it. Plain tweaks
  AFTER x-only tweaks are permitted (the spec leaves this optional; the
  official vector for it asserts byte-exactly here).
- **`SessionContext.tweaks: []const Tweak`** (default empty) — the spec's
  parallel `tweak_1..v`/`is_xonly_t_1..v` lists as one slice of
  `Tweak{ tweak, is_xonly }` values (no length-mismatch state exists).
  `getSessionValues` folds them over `keyAgg`'s output before computing
  `b`/`R`/`e`; the top-level `partialSigVerify` takes the same slice as a
  parameter (BIP327's own `PartialSigVerify` signature).
- Everything here is PUBLIC data (the aggregate key, the tweak values), so
  `applyTweak` uses variable-time `mulPublic`/branches per `keyAgg`'s own
  precedent; no secret ever enters the tweak path (the signer's secret is
  only re-corrected inside `sign` via the constant-time `Scalar.mul`s of
  `d = g·gacc·d'`, unchanged from v1).

## Out of scope

- **`DeterministicSign`** (BIP327 §"Deterministic and Stateless Signing
  for a Single Signer") — the optional single-signer convenience wrapper
  around `NonceGen`+`Sign` for the LAST signer in a session. Not part of
  the core flow the task scoped; `det_sign_vectors.json` was not fetched
  into `kat_vectors.zig`.
- **Zeroizing/secure-erase of `SecNonce`/`bip340.SecretKey`** — a
  consumer-side concern (see "Nonce reuse" above), not something a value
  type in this module can enforce.

## Done record — crypto-core implementation pass

The six formerly-stubbed cores, implemented in the scaffold's dependency
order (each later function calls into `getSessionValues`, which calls into
`keyAgg`), with the KAT group that pins each:

1. **`keyAgg`** — `KeyAggCoeffInternal` (the by-VALUE "second key"
   coefficient-1 rule, shared with `sign`/`partialSigVerifyInternal` via
   `keyAggCoeff`) + `Q = Σ a_i·P_i` (`mulPublic` per-term, PUBLIC-scalar
   variable-time per `bip340.verify`'s precedent, complete `add`
   accumulation) + the `is_infinite(Q)` rogue-key check. Pinned by all 4
   `key_agg` valid vectors (including both duplicated-key cases) byte-exact.
2. **`nonceAgg`** — `R_j = Σ R_{i,j}` for `j=1,2`, `cbytes_ext` encoding;
   an infinite sum is ENCODED (33 zero bytes), not rejected. Pinned by
   both `nonce_agg` valid vectors, including the point-at-infinity one.
3. **`getSessionValues`** — `b = int(H_noncecoef(aggnonce ‖ xbytes(Q) ‖
   m))`, `R' = R1 + b·R2` (infinity halves = identity in the sum),
   substitute `R = G` if `R'` is infinite, `e` via BIP340's own challenge
   tag. Pinned transitively by every `sign_verify`/`sig_agg` vector, and
   directly by the "Both halves of aggregate nonce correspond to point at
   infinity" signing vector (which exercises the `G` substitution).
4. **`sign`** — constant-time masked parity select of `k1/k2` on
   `has_even_y(R)` (byte-mask technique copied from `bip340.sign` step 7),
   `d = g·gacc·d'` (the security-critical secret-key negation), `s = k1 +
   b·k2 + e·a·d`, plus the spec's MANDATORY `partialSigVerifyInternal`
   self-check before returning (`error.SignatureVerificationFailed`,
   fail-closed). Pinned by all 6 `sign_verify` valid vectors byte-exact.
5. **`partialSigVerifyInternal`** — `Re* = ±(R*,1 + b·R*,2)` per
   `has_even_y(R)`, `g' = g·gacc`, equation `s·G == Re* + e·a·g'·P`
   (variable-time `mulPublic`; every failure path is an error return,
   never a panic; either side may legitimately be the identity). `g` comes
   from the SAME `gFromQ` helper `sign` uses, so signer and verifier
   cannot disagree on the flip. Pinned by `verify_fail` cases 0/1 — case 0
   ("wrong signature = negation of a valid one") is exactly the vector a
   flipped `g`/parity would turn into a false accept — and by every valid
   partial signature round-tripping through the top-level
   `partialSigVerify`.
6. **`partialSigAgg`** — `g` from `has_even_y(Q)` (`gFromQ` again), `s =
   Σs_i + e·g·tacc mod n` (tweak-general formula, `tacc = 0` in v1), `sig
   = xbytes(R) ‖ bytes(32,s)`. Pinned by the 2 untweaked `sig_agg` valid
   vectors byte-exact, each additionally verified by plain
   `bip340.verify` under the aggregate x-only key.

`SessionError` was widened to `KeyAggError || AggNonceError` so
`getSessionValues` never panics even on a hand-constructed (never-
`fromBytes`-validated) `SessionContext.aggnonce`. A 3-signer end-to-end
test (nonceGen → nonceAgg → sign → partialSigVerify → partialSigAgg →
`bip340.verify`) closes the loop on fresh, non-vector data, including a
cross-signer rejection check.

## Done record — tweaking pass (v2)

- **`KeyAggContext.applyTweak`** implemented per the "Tweaking" section
  above; `SessionError` widened again (`|| ApplyTweakError`) since
  BIP327's `GetSessionValues` runs the `ApplyTweak` loop itself.
  `sign`/`partialSigVerifyInternal`/`partialSigAgg` needed NO formula
  changes — audit confirmed all three already consumed the context's
  `gacc`/`tacc` (`d = g·sv.gacc·d'`, `g' = g·sv.gacc`, `s = Σs_i +
  e·g·sv.tacc`), never a hardcoded 1/0; the v1 "hardcoding" lived solely
  in `keyAgg`'s output values.
- **`partialSigVerify`** gained the `tweaks` parameter (BIP327's own
  top-level signature); the previously-embedded-but-skipped `sig_agg`
  tweaked cases 2/3 now assert byte-exactly, and the two key_agg tweak
  error cases (t = n out of range; plain tweak landing the single-key
  aggregate exactly on the point at infinity) were transcribed and assert
  against `applyTweak`.
- **KATs added**: all of `tweak_vectors.json` (5 valid chains — each
  signed byte-exact, accepted by the tweak-aware `partialSigVerify`, and
  REJECTED by an untweaked verify of the same psig; 1 error case, hit at
  both the `applyTweak` leaf and through `sign`), plus a second end-to-end
  test: 3 signers, a BIP341-shaped `TapTweak` x-only tweak, full protocol
  → the 64-byte aggregate verifies under the TWEAKED x-only key via plain
  `bip340.verify` and fails under the untweaked one.

## Verification

- KAT oracles: the official BIP327 test vectors, seven of the eight
  published JSON files under `bip-0327/vectors/` in `bitcoin/bips` (see
  `NOTICE`; only `det_sign_vectors.json` remains deliberately not
  embedded), transcribed into `src/kat_vectors.zig`.
- `zig build test-musig2` (Debug) and `-Doptimize=ReleaseFast`: 25 pass /
  0 skip (of 25 total) — every embedded official vector asserts for real
  (untweaked AND tweaked), plus the two end-to-end tests. `zig fmt
  --check modules/musig2/` clean; a repo-hygiene grep for
  scratch/home-directory leakage over this module's tree has no hits.
- Disk-vs-running test count (CONVENTIONS.md §6 step 3): counting
  top-level `test` blocks across `src/*.zig` sums to 25, matching
  `zig build test-musig2 --summary all`'s "25 total".
