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

## KAT plan — the assembly is anchored, the parameters cannot be

This module splits into an **assembly** (which hash output feeds which
XOR, the FO consistency check, where `fp12Pow` sits, where `U`/`V`/`W`
land in the wire encoding) and a set of **parameters** (`ciphersuite.
zig`'s hash tags, its `dst_g1`, the 32-byte block width, and the
canonical un-cubed `Gt` representation). `ibe.Scheme` makes the split
explicit — the assembly is written once and takes the ciphersuite as a
`comptime` parameter; `ibe`'s public API is `Scheme(ciphersuite)`. The
two halves are anchored completely differently, and saying so precisely
is the point of this section:

**The assembly IS externally anchored.** `kat_test.zig` section 5
instantiates `ibe.Scheme` with DRAND's parameters — drand's DSTs and
`IBE-H{2,3,4}` tags (reused from `modules/tlock`'s ciphersuite, not
restated), its 16-byte block width, and the `gt -> gt³` representation
adapter `kilic/bls12-381`'s final exponentiation requires — and
requires the result to reproduce, byte for byte, a genuine ciphertext
produced by drand's own Go `tle` CLI (the fixture frozen in
`modules/tlock/src/kat_test.zig` section 3; provenance in
`tlock/NOTICE`). It is `ibe.zig`'s own `encrypt`/`decrypt`/`fp12Pow`/
`Ciphertext` bodies doing the work — the same ones the default
instantiation uses, not a copy and not a re-derivation in another
language, either of which would be a sibling implementation and would
prove nothing. Both the byte-exact `encrypt` direction and the
`decrypt` direction are checked, plus rejection under a wrong key.

*Verified to have teeth, by mutation, twice.* (1) Swapping `V` and `W`
in `Ciphertext.toBytes` AND `fromBytes` — a consistent change, so the
codec still round-trips: `exit 1`, **40 pass / 2 fail**, and both
failures are section 5's. (2) Feeding `H4` the ciphertext's `V` instead
of `sigma` in `encrypt` AND `decrypt` — again consistent, so every
round-trip and tamper test still passes: `exit 1`, **40 pass / 2 fail**,
again only section 5's. Both mutations are exactly the systematic
assembly error a self-consistency suite is structurally blind to, and
in both cases the entire pre-existing suite stayed green while the
foreign fixture caught it. Reverted; `test-ibe` back to `exit 0`,
42/42.

**The parameters CANNOT be externally anchored — by construction, not
for want of effort.** RFC 9380 §3.1 *requires* every application to
choose its own domain-separation tag, so there is no external value for
`dst_g1` or `zig-libs/ibe/H{2,3,4}` to agree with: a tag of ours that
matched somebody else's would be a defect, not an anchor. The no-cube
decision (see "No drand-style cube" above) is the same kind of choice —
`tlock`'s cube exists only to match `kilic`'s final-exponentiation
convention, and with no external byte target any self-consistent
representation is correct. `Fr.reduceWide`-based `h3` likewise. These
are pinned by the self-consistency tests below and by nothing else, and
that is the end state, not an open to-do.

What `kat_test.zig` verifies on the parameter side:

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

- **drand-parameterised interop anchor (done)**: section 5, described
  above — `ibe.Scheme` under drand's parameters, byte-compared against
  a genuine Go-`tle`-produced ciphertext in both directions, plus a
  provenance check (`e(sig, G2gen) == e(h1(beaconId(round)), P_pub)`)
  so a typo in the transcribed fixture constants is a RED rather than a
  silently weaker anchor. This is the only test in the module whose
  expected bytes nobody here authored.

Underneath all of it, every primitive `ibe` is built from is itself
externally grounded: `bls12_381.pairing`/`hash_to_curve`/`g1`/`g2` are
byte-exact-KAT'd against the IETF pairing-friendly-curves draft and
RFC 9380 (`bls12_381`'s own `root.zig`).

**What is deliberately NOT claimed.** The anchor does not certify
`ibe`'s own DSTs, tags, `h3` construction, block width or no-cube
choice — section 5 runs with drand's, not ours, precisely because ours
have no external counterpart. Nor does a passing section 5 make `ibe`
drand-compatible: `Scheme(drand_ciphersuite)` exists only inside the
test file, and the published module is `Scheme(ciphersuite)` alone.
Anyone wanting real drand timelock interop wants `modules/tlock`.
Finally, the anchor exercises the assembly at drand's 16-byte block
width, so a defect that manifests ONLY at this module's 32-byte width
would slip past it — the bodies are generic in `cs.block_bytes` and use
no width-specific arithmetic, which is why that residual is judged
narrow rather than absent, but it is a residual and not nothing.

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

## Anchoring

**Anchor grade:** class B · oracle MIXED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** assembly byte-exact vs a genuine drand Go tle ciphertext: ibe.Scheme (comptime ciphersuite seam) driven with drand's parameters reproduces the fixture in kat_test.zig §5, encrypt and decrypt both directions; own DSTs/tags/h3/no-cube remain self-only and are unanchorable by construction (RFC 9380 §3.1 mandates a per-application DST, so no foreign value exists to match)

**How it got there.** The anchoring work landed. CLOSED 2026-08-09: the original NOTE was wrong on its own terms — no external implementation of THIS scheme exists, but this module's assembly is not scheme-specific. Split ibe.zig into an ASSEMBLY (which hash feeds which XOR, the FO consistency check, fp12Pow, the U||V||W encoding) and PARAMETERS (DSTs, tags, block width, Gt representation) via a comptime `Scheme(ciphersuite)` seam — the published API is Scheme(ciphersuite), unchanged. kat_test.zig §5 then instantiates THAT SAME CODE with drand's parameters (tlock's ciphersuite, imported as a test-only dep, plus the gt->gt³ adapter kilic's final exponentiation needs) and requires it to reproduce, byte for byte, the genuine Go-tle-produced ciphertext modules/tlock already had frozen — encrypt direction and decrypt direction, plus rejection under a wrong key, plus a pairing-identity check binding the transcribed pubkey/signature/identity so a typo is a RED. Explicitly NOT the py_ecc re-derivation the audit finding proposed: writing our own assembly a second time in Python would be a sibling, and a sibling for exactly the layer that lacked an oracle. Mutation-tested TWICE, both times consistently on both sides so the self-consistency layer stays blind: (1) V/W swapped in Ciphertext.toBytes+fromBytes, (2) H4 fed ct.V instead of sigma in encrypt+decrypt — each gave exit 1, 40 pass / 2 fail, with the ONLY failures being the two new drand tests while all 40 pre-existing round-trip/tamper/pairing tests stayed green. Reverted; test-ibe exit 0, 42/42. RESIDUAL, stated in SPEC.md/NOTICE/README/kat_test.zig header rather than papered over: the DST strings and the no-cube decision stay self-anchored forever — RFC 9380 §3.1 requires each application to choose its own DST, so an ibe DST matching someone else's would be a defect, not an anchor.
