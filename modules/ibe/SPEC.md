# ibe — SPEC

Standalone Boneh-Franklin Identity-Based Encryption over `bls12_381` —
see [README.md](README.md) for purpose and API. Provenance: see
[NOTICE](NOTICE).

**Status: REAL — fully implemented.** `ciphersuite.zig` (hashes/DSTs),
`ibe.Ciphertext` (wire struct + codec), `ibe.setup`/`ibe.extract` (the
PKG API), and `ibe.encrypt`/`ibe.decrypt` (the BF-IBE FullIdent core)
are all real and tested.

## The construction (Boneh-Franklin "FullIdent", CRYPTO 2001 §4.2)

```
setup(io):                                [REAL — ibe.setup]
  msk = Fr.random(io)
  mpk = msk · G2_generator

extract(msk, id):                         [REAL — ibe.extract]
  Qid = H1(id) = hashToCurveG1(id, dst_g1)
  return msk · Qid                        ∈ G1

encrypt(mpk, id, M, sigma):                [REAL — ibe.encrypt]
  Qid   = H1(id)
  Gid   = pairing(Qid, mpk) ∈ Gt
  r     = H3(sigma, M) ∈ Fr
  U     = r · G2_generator ∈ G2
  gid_r = Gid^r ∈ Gt                      (Gt SCALAR EXPONENTIATION — fp12Pow)
  V     = sigma XOR H2(gid_r)
  W     = M XOR H4(sigma)
  return (U, V, W)

decrypt(d_id, (U,V,W)):                    [REAL — ibe.decrypt]
  gid_r = pairing(d_id, U) ∈ Gt           (ONE pairing call — bilinearity gives gid_r for free)
  sigma = V XOR H2(gid_r)
  M     = W XOR H4(sigma)
  r'    = H3(sigma, M)
  if r'·G2_generator != U: REJECT (error.FoCheckFailed)   — Fiat-Shamir-Okamoto CCA check
  return M
```

`H1`/`H2`/`H3`/`H4` are this module's OWN SHA-256/SHA-512-based
constructions (`ciphersuite.h1`/`h2`/`h3`/`h4` — see that file's doc
comments for the exact byte layout). Unlike `tlock`'s `ciphersuite.h3`
(a little-endian rejection-sampling loop pinned to drand/kyber's exact
Go construction), `ibe.ciphersuite.h3` uses `Fr.reduceWide` over a
SHA-512 digest — a direct, spec-sanctioned hash-to-scalar reduction
(RFC 9380 §5's `hash_to_field` shape: draw more bits than the field
needs, reduce mod `r`); simpler, with no external byte-exact target to
match.

## Correctness identity

`decrypt`'s single pairing call recovers exactly what `encrypt` had to
exponentiate for, by bilinearity:

```
e(d_id, U) = e(msk·Qid, r·G2gen)
           = e(Qid, G2gen)^(msk·r)
           = e(Qid, msk·G2gen)^r
           = e(Qid, mpk)^r
           = Gid^r
```

`kat_test.zig`'s "pairing consistency" test checks this identity
DIRECTLY (recomputing `Gid`/`r`/`U` and comparing `pairing(d_id, U)`
against `fp12Pow(Gid, r)`), not merely inferring it from a successful
round trip.

## `Gt` (`Fp12`) scalar exponentiation

`encrypt` needs `Gid^r`; `bls12_381.Fp12` exports no `pow`. Same
resolution `tlock` already took (`tlock/SPEC.md`'s "Known gap", option
1): a module-local `fp12Pow` in `ibe.zig` — a constant-time
square-and-multiply-ALWAYS loop over `Fp12.square`/`.mul` and a
component-wise `Fp2.ctSelect` lift, adapted directly from `tlock.zig`'s
implementation (identical construction; `r = H3(sigma, M)` is
secret-derived in both modules, so the exponent is treated like a
secret scalar in both). Its exponentiation law is pinned ungated
against pairing bilinearity (`e(P,Q)^r == e(rP,Q)`) in both `ibe.zig`'s
own tests and `kat_test.zig`.

## No drand-style cube

`tlock.zig`'s `encrypt`/`decrypt` apply a private `gtToDrandRepr`
(`gt -> gt³`) adapter before every `ciphersuite.h2` call, because
`tlock` must byte-exactly match `kilic/bls12-381`'s pairing convention
(drand's actual Go implementation), whose final exponentiation computes
a fixed CUBE of the canonical pairing value this repo's
`bls12_381.pairing` implements — see `tlock/SPEC.md`'s "Gt
serialization" section for the full derivation.

**`ibe` applies no such cube, deliberately.** This module is NOT a
specialization of any external system — there is no third party's
`GT.ToBytes`/final-exponentiation convention to match. `encrypt` and
`decrypt` both call `bls12_381.pairing.pairing` (and the shared
`fp12Pow`) directly and feed `ciphersuite.h2` the CANONICAL,
un-cubed `Fp12` representation on both sides. Correctness only requires
that both sides agree — which the bilinearity identity above already
guarantees regardless of which final-exponentiation convention
`bls12_381.pairing` happens to implement (`(gid)^r` computed on one
side, `e(d_id, U)` computed on the other, are the SAME group element
under `bls12_381.pairing`'s own convention, whatever that convention
is). Applying `tlock`'s cube here would be pure cargo-culting: cubing
BOTH sides consistently would still work (bilinearity commutes with any
fixed power, same argument `tlock/SPEC.md` makes for why every
self-consistent test passes under either convention), but there is no
reason to add the extra `Fp12.square`+`Fp12.mul` per call when nothing
external constrains the representation. `kat_test.zig`'s "pairing
consistency" test pins this directly by comparing the canonical,
un-cubed `pairing(d_id, U)` against the canonical, un-cubed
`fp12Pow(Gid, r)`.

## KAT plan — self-consistent, honestly

**No external BF-IBE-over-BLS12-381 test vector exists** for this
module to check against: `tlock` can byte-exact-verify against a real
drand-Go-produced ciphertext because it specializes a widely-deployed
external system; `ibe` is this repo's own standalone scheme (a
caller-run PKG over an arbitrary identity string), which no other
library publishes vectors for. What `kat_test.zig` verifies instead:

- **Round-trip (done)**: `setup -> extract -> encrypt -> decrypt`
  recovers the original message, across five distinct
  `(identity, message)` pairs including an empty-string identity and a
  policy-string identity; a second test uses `ciphersuite.randomSigma`
  (the production entropy path, not a fixed KAT sigma); a third
  confirms `encrypt` is deterministic given fixed inputs.
- **Pairing consistency (done)**: `e(d_id, U) == fp12Pow(Gid, r)`
  checked directly on a known case (see "Correctness identity" above),
  plus the `Extract`-correctness identity `e(d_id, G2gen) ==
  e(H1(id), mpk)` a caller crossing a trust boundary would check (the
  same idiom `tlock`'s own pairing-sanity test uses for a beacon round
  signature).
- **`fp12Pow` law (done)**: `base^0`/`base^1`, exponent additivity, and
  the bilinearity cross-check `e(P,Q)^r == e(rP,Q)` — pinned in both
  `ibe.zig`'s own tests (mirroring `tlock.zig`'s identical tests) and
  `kat_test.zig`.
- **Soundness/CCA (done)**: tampered `U`/`V`/`W` (three separate
  tests), a random `G1` point used as `d_id` (not a real extracted
  key), `extract`-for-`id_A` used against a ciphertext encrypted to
  `id_B`, and a private key extracted under a DIFFERENT PKG's `msk` —
  all six must return `error.FoCheckFailed`, never a garbage plaintext.

This is meaningful, not weak, because every primitive `ibe` is built
from is ALREADY externally grounded: `bls12_381.pairing`/
`hash_to_curve`/`g1`/`g2` are byte-exact-KAT'd against the IETF
pairing-friendly-curves draft and RFC 9380 (`bls12_381`'s own
`root.zig`), and the encrypt/decrypt ASSEMBLY (which hash feeds which
XOR, the FO consistency check, the `fp12Pow` construction) is the exact
shape `tlock`'s sibling module already proved byte-exact against a
genuine drand-Go-produced ciphertext. What `ibe` adds on top of that
proven shape — its own DSTs/hash tags, `Fr.reduceWide`-based `h3`
instead of rejection sampling, and no drand-style cube — is exactly the
surface these self-consistency tests exercise directly.

## Honest tier note

This module is a full **Sonnet-tier** adaptation, not a Fable-hard
build: the hard pairing-based `encrypt`/`decrypt` core (the actual
irreducible cryptographic difficulty in any BF-IBE implementation —
getting the FO transform, the `Gt` exponentiation, and the bilinearity
bookkeeping right) was already proven by the sibling `tlock` module's
Fable pass. Building `ibe` was: (1) recognizing which parts of
`tlock.zig` generalize directly (the entire `encrypt`/`decrypt`/
`fp12Pow`/`Ciphertext` shape, essentially unchanged) versus which parts
are drand-interop-specific and must NOT be copied (the beacon-ID
digest format, the little-endian `h3` rejection-sampling counter, and
— most importantly — the `gtToDrandRepr` cube, whose absence had to be
justified, not merely omitted by oversight); and (2) the genuinely
trivial `Setup`/`Extract` (a scalar-times-generator and a
scalar-times-point-on-`G1`, both already-existing `bls12_381`
primitives). No new cryptographic construction, no new field/group/
pairing math, and no unresolved hard problem remain in this module.

## Out of scope

- Arbitrary-length payload encryption. `Ciphertext`'s `V`/`W` are fixed
  32-byte blocks; larger payloads are expected to be encrypted with a
  symmetric scheme keyed by this module's output (KEM-then-DEM), the
  same layering `tlock`'s own module doc comment documents.
- PQ-hybrid composition (see `root.zig`'s "Honest limitations" —
  gating a `hqc` KEM ciphertext alongside this module's IBE layer) — a
  consumer-side decision, not this module's job.
- Threshold/DKG PKG operation (splitting `msk` across multiple parties
  so no single party can `extract` unilaterally) — `setup`/`extract`
  here are always single-PKG; a threshold variant would be a separate
  extension (this repo's `threshold_ecdsa`/`bls12_381.threshold` show
  the general pattern for other schemes) built on Part 6's Shamir/
  Feldman machinery, not in scope here.
- Hierarchical IBE (HIBE), anonymous IBE, or any Boneh-Franklin variant
  beyond the base "FullIdent" scheme.
